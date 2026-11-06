/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/keychain_mock.go -source keychain.go -package mocks

// Package auth resolves registry credentials from Kubernetes secrets and the
// docker config with kubelet's keyring semantics, and pushes changed ones to
// running daemons.
package auth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/log"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

// kubeconfigPollInterval is how often Run retries loading the kubeconfig.
const kubeconfigPollInterval = 5 * time.Second

// Keychain resolves registry credentials for image references.
type Keychain interface {
	// Run watches the kubesecret source and pushes changed credentials to
	// running daemons until ctx is done. It returns at once when kubesecret
	// is disabled.
	Run(ctx context.Context)

	// Resolve returns the base64 username:password credential for ref, "" for
	// anonymous access.
	Resolve(ctx context.Context, ref *registry.Reference) (string, error)

	// Synced reports whether every source finished its initial sync.
	Synced() bool
}

// keychain looks up the kubesecret source, then the docker config.
type keychain struct {
	// cfg is the kubesecret config.
	cfg config.KubeSecretAuthConfig

	// store lists the running daemons to push credentials to.
	store store.Store

	// kubeClient returns the API client of the kubeconfig.
	kubeClient func() (kubernetes.Interface, error)

	// secrets is the kubesecret source, nil until Run connects.
	secrets atomic.Pointer[kubeSecret]

	// docker is the docker config source.
	docker *dockerConfig
}

// New keychain interface. Nothing is watched until Run.
func New(cfg *config.Config, s store.Store) Keychain {
	k := &keychain{
		cfg:    cfg.Auth.KubeSecret,
		store:  s,
		docker: newDockerConfig(cfg.Auth.DockerConfig.Path),
	}
	k.kubeClient = k.newKubeClient

	return k
}

// Run watches the kubesecret source and pushes changed credentials to
// running daemons until ctx is done. It returns at once when kubesecret is
// disabled.
func (k *keychain) Run(ctx context.Context) {
	if !k.cfg.Enable {
		return
	}

	client, err := k.connect(ctx)
	if err != nil {
		return
	}

	p := newPusher(k, k.store)
	secrets, err := newKubeSecret(client, k.cfg.LabelSelector, p.enqueue)
	if err != nil {
		log.G(ctx).WithError(err).Error("watch registry secrets")
		return
	}

	k.secrets.Store(secrets)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { secrets.informer.RunWithContext(ctx) })
	p.run(ctx, secrets.synced)
}

// connect returns the API client once the kubeconfig loads. The installer
// keeps the kubeconfig on tmpfs, so after a reboot it appears only once the
// installer Pod runs again, which needs this snapshotter serving.
func (k *keychain) connect(ctx context.Context) (kubernetes.Interface, error) {
	var (
		client  kubernetes.Interface
		lastErr string
	)

	err := wait.PollUntilContextCancel(ctx, kubeconfigPollInterval, true, func(context.Context) (bool, error) {
		var err error
		client, err = k.kubeClient()
		if err != nil {
			// Log a failure once, not every poll.
			if err.Error() != lastErr {
				log.G(ctx).WithError(err).Warn("connect kubernetes, retrying")
				lastErr = err.Error()
			}

			return false, nil
		}

		return true, nil
	})

	return client, err
}

// newKubeClient returns the API client of the kubeconfig, or of the
// in-cluster config when the path is empty.
func (k *keychain) newKubeClient() (kubernetes.Interface, error) {
	restConfig, err := clientcmd.BuildConfigFromFlags("", k.cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", k.cfg.Kubeconfig, err)
	}

	return kubernetes.NewForConfig(restConfig)
}

// Resolve returns the base64 username:password credential for ref, "" for
// anonymous access.
func (k *keychain) Resolve(ctx context.Context, ref *registry.Reference) (string, error) {
	target := canonicalHost(ref.Host) + "/" + ref.Repository
	var creds []credential
	if secrets := k.secrets.Load(); secrets != nil {
		creds = secrets.lookup(target)
	}

	creds = append(creds, k.docker.lookup(ctx, target)...)
	for i, cred := range creds {
		auth := cred.basic()
		if auth == "" {
			continue
		}

		// Warn about other credentials of the same key this one shadows.
		for _, other := range creds[i+1:] {
			if other.key == cred.key && other.source != cred.source && other.basic() != "" && other.basic() != auth {
				log.G(ctx).WithFields(log.Fields{"registry": cred.key, "source": cred.source, "shadowed": other.source}).Warn("credential shadows another")
			}
		}

		return auth, nil
	}

	if len(creds) > 0 {
		return "", fmt.Errorf("no usable credential for %s: %d matching entries hold no username:password", target, len(creds))
	}

	return "", nil
}

// Synced reports whether every source finished its initial sync.
func (k *keychain) Synced() bool {
	if !k.cfg.Enable {
		return true
	}

	secrets := k.secrets.Load()
	return secrets != nil && secrets.synced()
}
