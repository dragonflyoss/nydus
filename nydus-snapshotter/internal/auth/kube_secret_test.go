/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

var (
	mockRegistryTarget = "registry.example.com/team/app"

	mockUpdatedAt = metav1.NewTime(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
)

func newMockSecret(namespace, name, resourceVersion, registry, username string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       namespace,
			Name:            name,
			ResourceVersion: resourceVersion,
			Labels:          map[string]string{"app": "nydus"},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: fmt.Appendf(nil, `{"auths":{%q:{"username":%q,"password":"pass"}}}`, registry, username),
		},
	}
}

func newMockUpdatedSecret(namespace, name, resourceVersion, registry, username string) *corev1.Secret {
	s := newMockSecret(namespace, name, resourceVersion, registry, username)
	s.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubectl", Time: &mockUpdatedAt}}
	return s
}

func newMockKubeSecret(changed *[][]string) *kubeSecret {
	return &kubeSecret{
		secrets:  make(map[string]*secret),
		onChange: func(keys []string) { *changed = append(*changed, keys) },
	}
}

func TestKubeSecret_lookup(t *testing.T) {
	tests := []struct {
		name   string
		events func(k *kubeSecret)
		expect func(t *testing.T, k *kubeSecret, changed [][]string)
	}{
		{
			name: "ties in namespace/name order",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("b", "x", "1", "registry.example.com", "b"))
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				creds := k.lookup(mockRegistryTarget)
				assert.Len(creds, 2)
				assert.Equal("a", creds[0].Username)
				assert.Equal("secret a/y", creds[0].source)
				assert.Equal("b", creds[1].Username)
			},
		},
		{
			name: "secret updated last wins",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.store(newMockUpdatedSecret("b", "x", "1", "registry.example.com", "b"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert.Equal(t, "b", k.lookup(mockRegistryTarget)[0].Username)
			},
		},
		{
			name: "updated secret wins",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.store(newMockSecret("b", "x", "1", "registry.example.com", "b"))
				k.update(newMockSecret("b", "x", "1", "registry.example.com", "b"), newMockUpdatedSecret("b", "x", "2", "registry.example.com", "b2"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				assert.Equal("b2", k.lookup(mockRegistryTarget)[0].Username)
				assert.Len(changed, 3)
			},
		},
		{
			name: "skip update of the same resource version",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.update(newMockSecret("a", "y", "1", "registry.example.com", "a"), newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert.Len(t, changed, 1)
			},
		},
		{
			name: "forget deleted secret",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.delete(newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
				assert.Equal([][]string{{"registry.example.com"}, {"registry.example.com"}}, changed)
			},
		},
		{
			name: "forget secret deleted while unwatched",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.delete(cache.DeletedFinalStateUnknown{Key: "a/y", Obj: newMockSecret("a", "y", "1", "registry.example.com", "a")})
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert.Empty(t, k.lookup(mockRegistryTarget))
			},
		},
		{
			name: "skip malformed secret",
			events: func(k *kubeSecret) {
				malformed := newMockSecret("a", "y", "1", "registry.example.com", "a")
				malformed.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":`)
				k.store(malformed)
				k.store(newMockSecret("b", "x", "1", "registry.example.com", "b"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				creds := k.lookup(mockRegistryTarget)
				assert.Len(creds, 1)
				assert.Equal("b", creds[0].Username)
			},
		},
		{
			name: "forget secret updated to malformed",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				malformed := newMockSecret("a", "y", "2", "registry.example.com", "a")
				malformed.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":`)
				k.update(newMockSecret("a", "y", "1", "registry.example.com", "a"), malformed)
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert.Empty(t, k.lookup(mockRegistryTarget))
			},
		},
		{
			name: "skip secret of another type",
			events: func(k *kubeSecret) {
				opaque := newMockSecret("a", "y", "1", "registry.example.com", "a")
				opaque.Type = corev1.SecretTypeOpaque
				k.store(opaque)
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
				assert.Empty(changed)
			},
		},
		{
			name: "secrets of other registries do not multiply",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "x", "1", "one.example.com", "a"))
				k.store(newMockSecret("a", "y", "1", "two.example.com", "b"))
				k.store(newMockSecret("a", "z", "1", "registry.example.com", "c"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				assert.Len(k.lookup("one.example.com/app"), 1)
				assert.Len(k.lookup("two.example.com/app"), 1)
				assert.Len(k.lookup(mockRegistryTarget), 1)
			},
		},
		{
			name: "report registry keys before and after an update",
			events: func(k *kubeSecret) {
				k.store(newMockSecret("a", "y", "1", "one.example.com", "a"))
				k.update(newMockSecret("a", "y", "1", "one.example.com", "a"), newMockSecret("a", "y", "2", "https://two.example.com/v2/", "a"))
			},
			expect: func(t *testing.T, k *kubeSecret, changed [][]string) {
				assert := assert.New(t)
				assert.Len(changed, 2)
				assert.ElementsMatch([]string{"one.example.com", "two.example.com"}, changed[1])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var changed [][]string
			k := newMockKubeSecret(&changed)
			tc.events(k)
			tc.expect(t, k, changed)
		})
	}
}

func TestKubeSecret_transform(t *testing.T) {
	tests := []struct {
		name   string
		secret func() *corev1.Secret
		expect func(t *testing.T, s *corev1.Secret)
	}{
		{
			name: "keep the times of data owners only",
			secret: func() *corev1.Secret {
				s := newMockSecret("a", "y", "1", "registry.example.com", "a")
				s.Data["extra"] = []byte("unread")
				s.Annotations = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"}
				s.ManagedFields = []metav1.ManagedFieldsEntry{
					{Manager: "creator", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data":{".":{}},"f:type":{}}`)}},
					{Manager: "labeler", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{}}}`)}},
					{Manager: "writer", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:stringData":{}}`)}},
				}
				return s
			},
			expect: func(t *testing.T, s *corev1.Secret) {
				assert := assert.New(t)
				assert.Empty(s.Annotations)
				assert.Equal([]string{corev1.DockerConfigJsonKey}, slices.Collect(maps.Keys(s.Data)))
				assert.Len(s.ManagedFields, 2)
				for _, f := range s.ManagedFields {
					assert.NotEqual("labeler", f.Manager)
					assert.Nil(f.FieldsV1)
					assert.Equal(&mockUpdatedAt, f.Time)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := (&kubeSecret{}).transform(tc.secret())
			assert.NoError(t, err)
			tc.expect(t, obj.(*corev1.Secret))
		})
	}
}

func TestKubeSecret_newKubeSecret(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector string
		objects       func() []*corev1.Secret
		expect        func(t *testing.T, k *kubeSecret, client *fake.Clientset, err error)
	}{
		{
			name:          "watch labelled secrets",
			labelSelector: "app=nydus",
			objects: func() []*corev1.Secret {
				labelled := newMockSecret("a", "y", "1", "registry.example.com", "a")
				labelled.Annotations = map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "{}"}
				unlabelled := newMockSecret("a", "z", "1", "registry.example.com", "z")
				unlabelled.Labels = nil
				return []*corev1.Secret{labelled, unlabelled}
			},
			expect: func(t *testing.T, k *kubeSecret, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Eventually(k.synced, 5*time.Second, 10*time.Millisecond)
				creds := k.lookup(mockRegistryTarget)
				assert.Len(creds, 1)
				assert.Equal("a", creds[0].Username)

				cached := k.informer.GetStore().List()
				assert.Len(cached, 1)
				assert.Empty(cached[0].(*corev1.Secret).Annotations)
				managedFields := cached[0].(*corev1.Secret).ManagedFields
				assert.NotEmpty(managedFields)
				assert.Nil(managedFields[0].FieldsV1)
				assert.NotNil(managedFields[0].Time)
			},
		},
		{
			name:          "secret updated after the initial list wins",
			labelSelector: "app=nydus",
			objects: func() []*corev1.Secret {
				return []*corev1.Secret{newMockSecret("a", "y", "1", "registry.example.com", "a")}
			},
			expect: func(t *testing.T, k *kubeSecret, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Eventually(k.synced, 5*time.Second, 10*time.Millisecond)
				_, err = client.CoreV1().Secrets("z").Create(t.Context(), newMockUpdatedSecret("z", "z", "", "registry.example.com", "z"), metav1.CreateOptions{})
				assert.NoError(err)
				assert.Eventually(func() bool {
					creds := k.lookup(mockRegistryTarget)
					return len(creds) == 2 && creds[0].Username == "z"
				}, 5*time.Second, 10*time.Millisecond)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset()
			for _, s := range tc.objects() {
				_, err := client.CoreV1().Secrets(s.Namespace).Create(t.Context(), s, metav1.CreateOptions{})
				assert.NoError(t, err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			k, err := newKubeSecret(client, tc.labelSelector, func([]string) {})
			if err == nil {
				go k.informer.RunWithContext(ctx)
			}

			tc.expect(t, k, client, err)
		})
	}
}
