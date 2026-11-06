/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
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
		name         string
		secrets      []*corev1.Secret
		dockerConfig string
		ref          *registry.Reference
		expect       func(t *testing.T, auth string, err error)
	}{
		{
			name:         "anonymous without a match",
			dockerConfig: mockDockerConfig,
			ref:          mockRegistryReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(auth)
			},
		},
		{
			name:         "docker config",
			dockerConfig: mockDockerConfig,
			ref:          mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBasic, auth)
			},
		},
		{
			name:         "kubesecret before docker config",
			secrets:      []*corev1.Secret{newMockSecret("a", "y", "1", "docker.io", "secret")},
			dockerConfig: `{"auths":{"docker.io/library":{"username":"file","password":"pass"}}}`,
			ref:          mockDockerHubReference,
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
			dockerConfig: mockDockerConfig,
			ref:          mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBasic, auth)
			},
		},
		{
			name:         "anonymous for an empty entry of a credential store",
			dockerConfig: `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"desktop"}`,
			ref:          mockDockerHubReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(auth)
			},
		},
		{
			name:         "fail when only tokens match",
			dockerConfig: `{"auths":{"registry.example.com":{"registrytoken":"token"}}}`,
			ref:          mockRegistryReference,
			expect: func(t *testing.T, auth string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "no usable credential for registry.example.com/team/app")
				assert.Empty(auth)
			},
		},
		{
			name: "secret updated last shadows another",
			secrets: []*corev1.Secret{
				newMockSecret("a", "y", "1", "registry.example.com", "a"),
				newMockUpdatedSecret("b", "x", "1", "registry.example.com", "b"),
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
			if tc.dockerConfig != "" {
				assert.NoError(t, os.WriteFile(path, []byte(tc.dockerConfig), 0o600))
			}

			k := &keychain{docker: newDockerConfig(path)}
			if len(tc.secrets) > 0 {
				var changed [][]string
				secrets := newMockKubeSecret(&changed)
				for _, s := range tc.secrets {
					secrets.store(s)
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
		secrets *kubeSecret
		expect  func(t *testing.T, synced bool)
	}{
		{
			name: "kubesecret disabled",
			expect: func(t *testing.T, synced bool) {
				assert.True(t, synced)
			},
		},
		{
			name:   "kubesecret connecting",
			enable: true,
			expect: func(t *testing.T, synced bool) {
				assert.False(t, synced)
			},
		},
		{
			name:    "kubesecret syncing",
			enable:  true,
			secrets: &kubeSecret{synced: func() bool { return false }},
			expect: func(t *testing.T, synced bool) {
				assert.False(t, synced)
			},
		},
		{
			name:    "kubesecret synced",
			enable:  true,
			secrets: &kubeSecret{synced: func() bool { return true }},
			expect: func(t *testing.T, synced bool) {
				assert.True(t, synced)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := &keychain{cfg: config.KubeSecretAuthConfig{Enable: tc.enable}, docker: newDockerConfig("")}
			if tc.secrets != nil {
				k.secrets.Store(tc.secrets)
			}
			tc.expect(t, k.Synced())
		})
	}
}

func TestKeychain_connect(t *testing.T) {
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
			k := New(cfg, nil).(*keychain)
			client, err := k.connect(ctx)
			tc.expect(t, k, client, err)
		})
	}
}

func TestKeychain_Run(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, client *fake.Clientset, received func() []string)
	}{
		{
			name: "push secret changes to the daemon",
			expect: func(t *testing.T, client *fake.Clientset, received func() []string) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return len(received()) == 1 }, 5*time.Second, 10*time.Millisecond)
				assert.Equal([]string{"YTpwYXNz"}, received())

				rotated := newMockSecret("a", "y", "2", "registry.example.com", "b")
				_, err := client.CoreV1().Secrets("a").Update(t.Context(), rotated, metav1.UpdateOptions{})
				assert.NoError(err)
				assert.Eventually(func() bool { return len(received()) == 2 }, 5*time.Second, 10*time.Millisecond)
				assert.Equal([]string{"YTpwYXNz", "YjpwYXNz"}, received())

				unrelated := newMockSecret("a", "z", "1", "registry.example.com/other", "c")
				_, err = client.CoreV1().Secrets("a").Create(t.Context(), unrelated, metav1.CreateOptions{})
				assert.NoError(err)
				assert.NoError(client.CoreV1().Secrets("a").Delete(t.Context(), "y", metav1.DeleteOptions{}))
				assert.Never(func() bool { return len(received()) > 2 }, 200*time.Millisecond, 10*time.Millisecond)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var (
				mu    sync.Mutex
				auths []string
			)
			socket := filepath.Join(dir, "api.sock")
			listener, err := net.Listen("unix", socket)
			assert.NoError(t, err)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Auth string `json:"auth"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				auths = append(auths, body.Auth)
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
			})}
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { _ = server.Close() })

			instances, err := store.New(filepath.Join(dir, "nydusd.db"), time.Second)
			assert.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, instances.Close()) })
			instance := *mockInstance
			instance.APISocket = socket
			assert.NoError(t, instances.PutInstance(&instance))

			client := fake.NewClientset(newMockSecret("a", "y", "1", "registry.example.com", "a"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			k := &keychain{
				cfg:        config.KubeSecretAuthConfig{Enable: true},
				store:      instances,
				kubeClient: func() (kubernetes.Interface, error) { return client, nil },
				docker:     newDockerConfig(filepath.Join(dir, "config.json")),
			}
			done := make(chan struct{})
			go func() {
				k.Run(ctx)
				close(done)
			}()
			t.Cleanup(func() {
				cancel()
				<-done
			})

			tc.expect(t, client, func() []string {
				mu.Lock()
				defer mu.Unlock()
				return append([]string(nil), auths...)
			})
		})
	}
}
