/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"k8s.io/client-go/util/workqueue"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

const (
	// pusherWorkers is the number of push workers, as sample-controller runs.
	pusherWorkers = 2
)

// Run keeps the registry credentials of the daemons current and runs the
// preheats until ctx is done: it watches the keychain and pushes a changed
// credential to the daemons reading with it.
func (f *fileSystem) Run(ctx context.Context) {
	// A start is over, one way or the other, within the bound of a Mount.
	p := newPusher(f.keychain, f.store, f.newClient, f.mountBound(f.cfg.Load()))
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { f.keychain.Run(ctx, p.enqueue) })
	wg.Go(func() { f.runPreheats(ctx) })
	p.run(ctx)
}

// pusher keeps the registry credential of every recorded daemon current:
// when a credential may have changed it resolves each daemon's again and
// pushes the ones that differ from what the daemon was last given, refer to
// https://github.com/kubernetes/sample-controller/blob/master/controller.go.
type pusher struct {
	// keychain resolves credentials.
	keychain auth.Keychain

	// store lists the recorded daemons.
	store store.Store

	// newClient returns a client of a daemon API socket.
	newClient func(socket string) nydusd.Client

	// queue holds the chain IDs of the daemons to push to.
	queue workqueue.TypedRateLimitingInterface[string]

	// mu guards pushed.
	mu sync.Mutex

	// pushed holds, by chain ID, the last credential each daemon accepted or
	// rejected, so that it is not sent again.
	pushed map[string]pushRecord

	// startTimeout is the longest a daemon start takes.
	startTimeout time.Duration
}

// pushRecord is a credential one daemon accepted or rejected.
type pushRecord struct {
	// createdAt is the instance's creation time, telling a restarted daemon
	// apart.
	createdAt time.Time

	// sum is the credential's sha256, so the credential is not kept.
	sum [sha256.Size]byte
}

// newPusher returns a pusher that sends the credentials keychain resolves to
// the daemons recorded in s. A daemon start takes at most startTimeout.
func newPusher(keychain auth.Keychain, s store.Store, newClient func(socket string) nydusd.Client, startTimeout time.Duration) *pusher {
	return &pusher{
		keychain:     keychain,
		store:        s,
		newClient:    newClient,
		queue:        workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		pushed:       make(map[string]pushRecord),
		startTimeout: startTimeout,
	}
}

// enqueue queues every recorded daemon instead of matching daemons against
// what changed: a daemon whose credential is unchanged costs one lookup and
// no API call.
func (p *pusher) enqueue() {
	instances, err := p.store.ListInstances()
	if err != nil {
		log.L.WithError(err).Warn("list instances to push credentials")
		return
	}

	// Forget what was pushed to daemons torn down since.
	p.mu.Lock()
	maps.DeleteFunc(p.pushed, func(chainID string, _ pushRecord) bool {
		return !slices.ContainsFunc(instances, func(instance *store.Instance) bool { return instance.ChainID == chainID })
	})
	p.mu.Unlock()

	for _, instance := range instances {
		p.queue.Add(instance.ChainID)
	}
}

// run runs the workers until ctx is done.
func (p *pusher) run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	defer p.queue.ShutDown()

	for range pusherWorkers {
		wg.Go(func() {
			for p.processNextWorkItem(ctx) {
			}
		})
	}

	<-ctx.Done()
}

// processNextWorkItem pushes to the next queued daemon and reports false once
// the queue shuts down.
func (p *pusher) processNextWorkItem(ctx context.Context) bool {
	chainID, shutdown := p.queue.Get()
	if shutdown {
		return false
	}
	defer p.queue.Done(chainID)

	if err := p.push(ctx, chainID); err != nil {
		log.G(ctx).WithError(err).WithField("chain_id", chainID).Warn("push credential, retrying")
		p.queue.AddRateLimited(chainID)
		return true
	}

	p.queue.Forget(chainID)
	return true
}

// push resolves the credential of an instance again and pushes it to the
// daemon, unless the daemon already accepted or rejected it. Only failures
// worth a retry are returned.
func (p *pusher) push(ctx context.Context, chainID string) error {
	instance, err := p.store.GetInstance(chainID)
	if errdefs.IsNotFound(err) {
		p.forget(chainID)
		return nil
	}

	if err != nil {
		return err
	}

	// A daemon recorded without its version while its start may still run
	// resolved its credential before this change, so retry until it is
	// identified.
	if instance.Version == "" && p.starting(instance) {
		return fmt.Errorf("daemon %s is not identified yet", instance.Unit)
	}

	logger := log.G(ctx).WithField("unit", instance.Unit)
	ref, err := registry.ParseReference(instance.ImageRef)
	if err != nil {
		logger.WithError(err).Error("skip pushing credential")
		return nil
	}

	credential, err := p.keychain.Resolve(ctx, ref)
	if err != nil {
		logger.WithError(err).Error("skip pushing credential")
		return nil
	}

	// Keep the daemon's last credential when none is left, as after a
	// secret delete.
	if credential == "" {
		return nil
	}

	current := pushRecord{createdAt: instance.CreatedAt, sum: sha256.Sum256([]byte(credential))}
	p.mu.Lock()
	last, ok := p.pushed[chainID]
	p.mu.Unlock()
	if ok && last.sum == current.sum && last.createdAt.Equal(current.createdAt) {
		return nil
	}

	// Push only to a daemon that serves the call, which it lists as a
	// capability. A record older than its version tells nothing, so its
	// daemon is asked.
	if instance.Version != "" && !slices.Contains(instance.Capabilities, nydusd.CapabilityBackendAuthBasic) {
		metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported).Inc()
		logger.Debug("skip pushing credential to a daemon without the capability")
		p.record(chainID, current)
		return nil
	}

	// Without an answer the daemon may hold either credential, so the next
	// push is sent whatever was pushed before.
	answered, err := p.update(ctx, instance, credential)
	if !answered {
		p.forget(chainID)
		return err
	}

	p.record(chainID, current)
	return nil
}

// update sends a credential to a daemon and reports whether the daemon
// answered, accepting or rejecting it for good. Without an answer, the error
// is worth a retry; it is nil for a stopped daemon, which gets the credential
// when it starts.
func (p *pusher) update(ctx context.Context, instance *store.Instance, credential string) (bool, error) {
	logger := log.G(ctx).WithField("unit", instance.Unit)
	err := p.newClient(instance.APISocket).UpdateAuth(ctx, credential)
	switch {
	case err == nil:
		metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultSuccess).Inc()
		return true, nil
	case errdefs.IsNotImplemented(err):
		metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported).Inc()
		logger.WithError(err).Error("daemon does not support credential updates")
		return true, nil
	case errdefs.IsInvalidArgument(err), errdefs.IsPermissionDenied(err):
		// A retry sends the same credential and fails the same way.
		metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure).Inc()
		logger.WithError(err).Error("daemon rejected credential")
		return true, nil
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		// A starting daemon resolved its credential before this change, so
		// retry until it listens.
		if p.starting(instance) {
			return false, err
		}

		logger.WithError(err).Debug("skip pushing credential to a stopped daemon")
		return false, nil
	default:
		metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure).Inc()
		return false, err
	}
}

// starting reports whether the start of a daemon may still run, during which
// the daemon may not be identified or listening yet.
func (p *pusher) starting(instance *store.Instance) bool {
	return time.Since(instance.CreatedAt) < p.startTimeout
}

// record keeps the credential a daemon accepted or rejected.
func (p *pusher) record(chainID string, r pushRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pushed[chainID] = r
}

// forget drops the record of a daemon, so the next credential is sent.
func (p *pusher) forget(chainID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pushed, chainID)
}
