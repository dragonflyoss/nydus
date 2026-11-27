/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

var (
	mockDockerHubReference = &registry.Reference{
		Name:       "docker.io/library/ubuntu:24.04",
		Host:       "docker.io",
		Repository: "library/ubuntu",
	}

	mockRegistryReference = &registry.Reference{
		Name:       "registry.example.com/team/app:v1",
		Host:       "registry.example.com",
		Repository: "team/app",
	}

	mockKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:1
contexts:
- name: test
  context:
    cluster: test
current-context: test
`
)

func TestKeychain_Resolve(t *testing.T) {
	tests := []struct {
		name                 string
		secrets              []*corev1.Secret
		dockerConfigProvider string
		ref                  *registry.Reference
		expect               func(t *testing.T, auth string, err error)
	}{
		{
			name:                 "anonymous without a match",
			dockerConfigProvider: mockDockerConfig,
			ref:                  mockRegistryReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(auth)
			},
		},
		{
			name:                 "docker config",
			dockerConfigProvider: mockDockerConfig,
			ref:                  mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBasic, auth)
			},
		},
		{
			name:                 "kube secret before docker config",
			secrets:              []*corev1.Secret{mockSecret("a", "y", "1", "docker.io", "secret")},
			dockerConfigProvider: `{"auths":{"docker.io/library":{"username":"file","password":"pass"}}}`,
			ref:                  mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("c2VjcmV0OnBhc3M=", auth)
			},
		},
		{
			name: "skip token entries",
			secrets: []*corev1.Secret{
				{
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"docker.io":{"identitytoken":"token"}}}`)},
				},
			},
			dockerConfigProvider: mockDockerConfig,
			ref:                  mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBasic, auth)
			},
		},
		{
			name:                 "anonymous for an empty entry of a credential store",
			dockerConfigProvider: `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"desktop"}`,
			ref:                  mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(auth)
			},
		},
		{
			name:                 "fail when only tokens match",
			dockerConfigProvider: `{"auths":{"registry.example.com":{"registrytoken":"token"}}}`,
			ref:                  mockRegistryReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "no usable credential for registry.example.com/team/app")
				assert.Empty(auth)
			},
		},
		{
			name: "secret updated last shadows another",
			secrets: []*corev1.Secret{
				mockSecret("a", "y", "1", "registry.example.com", "a"),
				mockUpdatedSecret("b", "x", "1", "registry.example.com", "b"),
			},
			ref: mockRegistryReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("YjpwYXNz", auth)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if tc.dockerConfigProvider != "" {
				assert.NoError(t, os.WriteFile(path, []byte(tc.dockerConfigProvider), 0o600))
			}

			k := &keychain{docker: newDockerConfigProvider(path)}
			if len(tc.secrets) > 0 {
				secrets := &kubeSecretProvider{
					secrets:  make(map[string]*secret),
					synced:   func() bool { return true },
					onChange: func() {},
				}

				for _, s := range tc.secrets {
					secrets.add(s)
				}
				k.secrets.Store(secrets)
			}

			auth, err := k.Resolve(t.Context(), tc.ref)
			tc.expect(t, auth, err)
		})
	}
}

func TestKeychain_Synced(t *testing.T) {
	tests := []struct {
		name    string
		enable  bool
		secrets *kubeSecretProvider
		expect  func(t *testing.T, synced bool)
	}{
		{
			name: "kube secret disabled",
			expect: func(t *testing.T, synced bool) {
				assert := assert.New(t)
				assert.True(synced)
			},
		},
		{
			name:   "kube secret connecting",
			enable: true,
			expect: func(t *testing.T, synced bool) {
				assert := assert.New(t)
				assert.False(synced)
			},
		},
		{
			name:    "kube secret syncing",
			enable:  true,
			secrets: &kubeSecretProvider{synced: func() bool { return false }},
			expect: func(t *testing.T, synced bool) {
				assert := assert.New(t)
				assert.False(synced)
			},
		},
		{
			name:    "kube secret synced",
			enable:  true,
			secrets: &kubeSecretProvider{synced: func() bool { return true }},
			expect: func(t *testing.T, synced bool) {
				assert := assert.New(t)
				assert.True(synced)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := &keychain{cfg: config.AuthKubeSecretConfig{Enable: tc.enable}, docker: newDockerConfigProvider("")}
			if tc.secrets != nil {
				k.secrets.Store(tc.secrets)
			}
			tc.expect(t, k.Synced())
		})
	}
}

func TestKeychain_waitForKubeClient(t *testing.T) {
	tests := []struct {
		name       string
		kubeconfig string
		expect     func(t *testing.T, k *keychain, client kubernetes.Interface, err error)
	}{
		{
			name:       "connect with the kubeconfig",
			kubeconfig: mockKubeconfig,
			expect: func(t *testing.T, k *keychain, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotNil(client)
			},
		},
		{
			name: "wait for a missing kubeconfig",
			expect: func(t *testing.T, k *keychain, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.False(k.Synced())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Auth.KubeSecret.Enable = true
			cfg.Auth.KubeSecret.Kubeconfig = filepath.Join(t.TempDir(), "kubeconfig")
			if tc.kubeconfig != "" {
				assert.NoError(t, os.WriteFile(cfg.Auth.KubeSecret.Kubeconfig, []byte(tc.kubeconfig), 0o600))
			}

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			k := New(cfg).(*keychain)
			client, err := k.waitForKubeClient(ctx)
			tc.expect(t, k, client, err)
		})
	}
}

func TestKeychain_Run(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, k *keychain, client *fake.Clientset, changes *atomic.Int32, done <-chan struct{})
	}{
		{
			name: "report the synced secrets once, then every change",
			expect: func(t *testing.T, k *keychain, client *fake.Clientset, changes *atomic.Int32, done <-chan struct{}) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return changes.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
				assert.True(k.Synced())
				auth, err := k.Resolve(t.Context(), mockRegistryReference)
				assert.NoError(err)
				assert.Equal("YTpwYXNz", auth)

				rotated := mockSecret("a", "y", "2", "registry.example.com", "b")
				_, err = client.CoreV1().Secrets("a").Update(t.Context(), rotated, metav1.UpdateOptions{})
				assert.NoError(err)
				assert.Eventually(func() bool { return changes.Load() == 2 }, 5*time.Second, 10*time.Millisecond)
				auth, err = k.Resolve(t.Context(), mockRegistryReference)
				assert.NoError(err)
				assert.Equal("YjpwYXNz", auth)

				assert.NoError(client.CoreV1().Secrets("a").Delete(t.Context(), "y", metav1.DeleteOptions{}))
				assert.Eventually(func() bool { return changes.Load() == 3 }, 5*time.Second, 10*time.Millisecond)
				auth, err = k.Resolve(t.Context(), mockRegistryReference)
				assert.NoError(err)
				assert.Empty(auth)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset(mockSecret("a", "y", "1", "registry.example.com", "a"))
			ctx, cancel := context.WithCancel(t.Context())
			k := &keychain{
				cfg:        config.AuthKubeSecretConfig{Enable: true},
				kubeClient: func() (kubernetes.Interface, error) { return client, nil },
				docker:     newDockerConfigProvider(filepath.Join(t.TempDir(), "config.json")),
			}

			changes := &atomic.Int32{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				k.Run(ctx, func() { changes.Add(1) })
			}()
			t.Cleanup(func() {
				cancel()
				<-done
			})

			tc.expect(t, k, client, changes, done)
		})
	}
}
