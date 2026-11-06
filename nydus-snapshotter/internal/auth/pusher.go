/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

const (
	// pusherWorkers is the number of push workers, as sample-controller runs.
	pusherWorkers = 2

	// resultSuccess is a credential the daemon accepted.
	resultSuccess = "success"

	// resultFailure is a push the daemon rejected or that failed.
	resultFailure = "failure"

	// resultUnsupported is a daemon without the auth route.
	resultUnsupported = "unsupported"
)

// pusher re-resolves the credential of instances whose registry has a
// changed secret, and pushes it to their daemons, refer to
// https://github.com/kubernetes/sample-controller/blob/master/controller.go.
type pusher struct {
	// keychain resolves credentials.
	keychain Keychain

	// store lists the running daemons.
	store store.Store

	// newClient returns the API client of a daemon socket.
	newClient func(socket string) nydusd.Client

	// queue holds chain IDs to push.
	queue workqueue.TypedRateLimitingInterface[string]

	// mu guards pushed.
	mu sync.Mutex

	// pushed holds the last credential pushed by chain ID.
	pushed map[string]pushRecord
}

// pushRecord is a credential pushed to one daemon.
type pushRecord struct {
	// createdAt is the instance's creation time, telling a restarted daemon
	// apart.
	createdAt time.Time

	// sum is the credential's sha256, so the credential is not kept.
	sum [sha256.Size]byte
}

// New credential pusher.
func newPusher(keychain Keychain, s store.Store) *pusher {
	return &pusher{
		keychain:  keychain,
		store:     s,
		newClient: nydusd.NewClient,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		pushed:    make(map[string]pushRecord),
	}
}

// enqueue queues the chain IDs of the instances whose registry host matches
// the host of a registry key.
func (p *pusher) enqueue(keys []string) {
	instances, err := p.store.ListInstances()
	if err != nil {
		log.L.WithError(err).Warn("list instances to push credentials")
		return
	}

	// Forget what was pushed to daemons torn down since.
	p.mu.Lock()
	for chainID := range p.pushed {
		if !slices.ContainsFunc(instances, func(instance *store.Instance) bool { return instance.ChainID == chainID }) {
			delete(p.pushed, chainID)
		}
	}
	p.mu.Unlock()

	for _, instance := range instances {
		host := canonicalHost(instance.RegistryHost)
		if slices.ContainsFunc(keys, func(key string) bool {
			keyHost, _, _ := strings.Cut(key, "/")
			matched, _ := urlsMatchStr(keyHost, host)
			return matched
		}) {
			p.queue.Add(instance.ChainID)
		}
	}
}

// run starts the workers once synced reports true, and stops them when ctx
// is done.
func (p *pusher) run(ctx context.Context, synced cache.InformerSynced) {
	var wg sync.WaitGroup
	defer wg.Wait()
	defer p.queue.ShutDown()

	if !cache.WaitForCacheSync(ctx.Done(), synced) {
		return
	}

	for range pusherWorkers {
		wg.Go(func() {
			for p.processNextItem(ctx) {
			}
		})
	}

	<-ctx.Done()
}

// processNextItem pushes the next queued chain ID, and reports false once
// the queue shuts down.
func (p *pusher) processNextItem(ctx context.Context) bool {
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
// daemon when it differs from the last one pushed. Only failures worth a
// retry are returned.
func (p *pusher) push(ctx context.Context, chainID string) error {
	instance, err := p.store.GetInstance(chainID)
	if errdefs.IsNotFound(err) {
		p.mu.Lock()
		delete(p.pushed, chainID)
		p.mu.Unlock()
		return nil
	}

	if err != nil {
		return err
	}

	logger := log.G(ctx).WithField("chain_id", chainID)
	ref, err := registry.ParseReference(instance.ImageRef)
	if err != nil {
		logger.WithError(err).Error("skip pushing credential")
		return nil
	}

	auth, err := p.keychain.Resolve(ctx, ref)
	if err != nil {
		logger.WithError(err).Error("skip pushing credential")
		return nil
	}

	// Keep the daemon's last credential when none is left, as after a
	// secret delete.
	if auth == "" {
		return nil
	}

	current := pushRecord{createdAt: instance.CreatedAt, sum: sha256.Sum256([]byte(auth))}
	p.mu.Lock()
	last, ok := p.pushed[chainID]
	p.mu.Unlock()
	if ok && last.sum == current.sum && last.createdAt.Equal(current.createdAt) {
		return nil
	}

	if err := p.newClient(instance.APISocket).UpdateAuth(ctx, auth); err != nil {
		switch {
		case errdefs.IsNotImplemented(err):
			metrics.AuthUpdateTotal.WithLabelValues(resultUnsupported).Inc()
			logger.WithError(err).Error("daemon does not support credential updates")
			return nil
		case errdefs.IsInvalidArgument(err), errdefs.IsPermissionDenied(err):
			// A retry sends the same credential and fails the same way.
			metrics.AuthUpdateTotal.WithLabelValues(resultFailure).Inc()
			logger.WithError(err).Error("daemon rejected credential")
			return nil
		case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
			// A daemon that is not running gets the credential when it starts.
			logger.WithError(err).Debug("skip pushing credential to a stopped daemon")
			p.mu.Lock()
			delete(p.pushed, chainID)
			p.mu.Unlock()
			return nil
		default:
			metrics.AuthUpdateTotal.WithLabelValues(resultFailure).Inc()
			return err
		}
	}

	metrics.AuthUpdateTotal.WithLabelValues(resultSuccess).Inc()
	p.mu.Lock()
	p.pushed[chainID] = current
	p.mu.Unlock()
	return nil
}
