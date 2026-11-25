/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/keychain_mock.go -source keychain.go -package mocks

// Package auth resolves registry credentials from Kubernetes secrets and the
// docker config with kubelet's keyring semantics.
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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

// kubeconfigPollInterval is how often Run retries loading the kubeconfig.
const kubeconfigPollInterval = 5 * time.Second

// Keychain resolves registry credentials for image references.
type Keychain interface {
	// Run watches the kube_secret provider until ctx is done and calls
	// onChange when a credential may have changed: once the secrets are
	// synced, then on every secret change. The caller runs it only with
	// kube_secret enabled. A changed docker config is read by the next
	// Resolve and reported by no call.
	Run(ctx context.Context, onChange func())

	// Resolve returns the base64 username:password credential for ref, "" for
	// anonymous access.
	Resolve(ctx context.Context, ref *registry.Reference) (string, error)

	// Synced reports whether every provider finished its initial sync.
	// Without kube_secret there is none to wait for.
	Synced() bool
}

// keychain looks up the kube_secret provider, then the docker config
// provider.
type keychain struct {
	// cfg is the kube_secret config.
	cfg config.AuthKubeSecretConfig

	// kubeClient returns the API client of the kubeconfig.
	kubeClient func() (kubernetes.Interface, error)

	// secrets is the kube_secret provider, nil until Run connects.
	secrets atomic.Pointer[kubeSecretProvider]

	// docker is the docker config provider.
	docker *dockerConfigProvider
}

// New returns a keychain. Nothing is watched until Run.
func New(cfg *config.Config) Keychain {
	k := &keychain{
		cfg:    cfg.Auth.KubeSecret,
		docker: newDockerConfigProvider(cfg.Auth.DockerConfig.Path),
	}
	k.kubeClient = k.newKubeClient

	return k
}

// Run watches the kube_secret provider until ctx is done and calls onChange
// when a credential may have changed: once the secrets are synced, then on
// every secret change. The caller runs it only with kube_secret enabled. A
// changed docker config is read by the next Resolve and reported by no call.
func (k *keychain) Run(ctx context.Context, onChange func()) {
	// connect fails only once ctx is done.
	client, err := k.waitForKubeClient(ctx)
	if err != nil {
		return
	}

	secrets, err := newKubeSecretProvider(client, k.cfg.LabelSelector, onChange)
	if err != nil {
		log.G(ctx).WithError(err).Error("watch registry secrets")
		return
	}

	k.secrets.Store(secrets)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { secrets.informer.RunWithContext(ctx) })

	// The secrets listed first are reported in one call, as they may have
	// changed while nothing watched them.
	if cache.WaitForCacheSync(ctx.Done(), secrets.synced) {
		onChange()
	}
}

// waitForKubeClient returns the API client once the kubeconfig loads. The
// installer keeps the kubeconfig on tmpfs, so after a reboot it appears only
// once the installer Pod runs again, which needs this snapshotter serving.
func (k *keychain) waitForKubeClient(ctx context.Context) (kubernetes.Interface, error) {
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
	target := newRegistryKey(ref.Host, "/"+ref.Repository)
	var creds []credential
	if secrets := k.secrets.Load(); secrets != nil {
		creds = secrets.lookup(target)
	}

	creds = append(creds, k.docker.lookup(ctx, target)...)
	for i, cred := range creds {
		if auth := cred.basic(); auth != "" {
			k.logShadowed(ctx, cred, creds[i+1:])
			return auth, nil
		}
	}

	if len(creds) > 0 {
		return "", fmt.Errorf("no usable credential for %s: %d matching entries hold no username:password", target, len(creds))
	}

	return "", nil
}

// logShadowed tells, at debug level, which credentials of the same key the
// one in use shadows: namespaces each holding their own secret of a registry
// shadow one another on every lookup.
func (k *keychain) logShadowed(ctx context.Context, used credential, rest []credential) {
	auth := used.basic()
	for _, other := range rest {
		if other.key != used.key || other.source == used.source {
			continue
		}

		if shadowed := other.basic(); shadowed != "" && shadowed != auth {
			log.G(ctx).WithFields(log.Fields{"registry": used.key, "source": used.source, "shadowed": other.source}).Debug("credential shadows another")
		}
	}
}

// Synced reports whether every provider finished its initial sync. Without
// kube_secret there is none to wait for.
func (k *keychain) Synced() bool {
	secrets := k.secrets.Load()
	return !k.cfg.Enable || secrets != nil && secrets.synced()
}
