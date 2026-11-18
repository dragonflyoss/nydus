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
	mockRegistryTarget registryKey = "registry.example.com/team/app"

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

func newTestKubeSecretProvider(synced bool, changed *int) *kubeSecretProvider {
	return &kubeSecretProvider{
		secrets:  make(map[string]*secret),
		synced:   func() bool { return synced },
		onChange: func() { *changed++ },
	}
}

func TestKubeSecretProvider_lookup(t *testing.T) {
	tests := []struct {
		name   string
		events func(k *kubeSecretProvider)
		expect func(t *testing.T, k *kubeSecretProvider, changed int)
	}{
		{
			name: "ties in namespace/name order",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("b", "x", "1", "registry.example.com", "b"))
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
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
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.add(newMockUpdatedSecret("b", "x", "1", "registry.example.com", "b"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Equal("b", k.lookup(mockRegistryTarget)[0].Username)
			},
		},
		{
			name: "updated secret wins",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.add(newMockSecret("b", "x", "1", "registry.example.com", "b"))
				k.update(newMockSecret("b", "x", "1", "registry.example.com", "b"), newMockUpdatedSecret("b", "x", "2", "registry.example.com", "b2"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Equal("b2", k.lookup(mockRegistryTarget)[0].Username)
				assert.Equal(3, changed)
			},
		},
		{
			name: "skip update of the same resource version",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.update(newMockSecret("a", "y", "1", "registry.example.com", "a"), newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Equal(1, changed)
			},
		},
		{
			name: "forget deleted secret",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.delete(newMockSecret("a", "y", "1", "registry.example.com", "a"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
				assert.Equal(2, changed)
			},
		},
		{
			name: "forget secret deleted while unwatched",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				k.delete(cache.DeletedFinalStateUnknown{Key: "a/y", Obj: newMockSecret("a", "y", "1", "registry.example.com", "a")})
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
			},
		},
		{
			name: "skip malformed secret",
			events: func(k *kubeSecretProvider) {
				malformed := newMockSecret("a", "y", "1", "registry.example.com", "a")
				malformed.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":`)
				k.add(malformed)
				k.add(newMockSecret("b", "x", "1", "registry.example.com", "b"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				creds := k.lookup(mockRegistryTarget)
				assert.Len(creds, 1)
				assert.Equal("b", creds[0].Username)
			},
		},
		{
			name: "forget secret updated to malformed",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "y", "1", "registry.example.com", "a"))
				malformed := newMockSecret("a", "y", "2", "registry.example.com", "a")
				malformed.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":`)
				k.update(newMockSecret("a", "y", "1", "registry.example.com", "a"), malformed)
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
			},
		},
		{
			name: "skip an object that is no secret",
			events: func(k *kubeSecretProvider) {
				k.add("no secret")
				k.update("no secret", newMockSecret("a", "y", "2", "registry.example.com", "a"))
				k.update(newMockSecret("a", "y", "1", "registry.example.com", "a"), "no secret")
				k.delete("no secret")
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
				assert.Zero(changed)
			},
		},
		{
			name: "skip secret of another type",
			events: func(k *kubeSecretProvider) {
				opaque := newMockSecret("a", "y", "1", "registry.example.com", "a")
				opaque.Type = corev1.SecretTypeOpaque
				k.add(opaque)
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Empty(k.lookup(mockRegistryTarget))
			},
		},
		{
			name: "secrets of other registries do not multiply",
			events: func(k *kubeSecretProvider) {
				k.add(newMockSecret("a", "x", "1", "one.example.com", "a"))
				k.add(newMockSecret("a", "y", "1", "two.example.com", "b"))
				k.add(newMockSecret("a", "z", "1", "registry.example.com", "c"))
			},
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Len(k.lookup("one.example.com/app"), 1)
				assert.Len(k.lookup("two.example.com/app"), 1)
				assert.Len(k.lookup(mockRegistryTarget), 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var changed int
			k := newTestKubeSecretProvider(true, &changed)
			tc.events(k)
			tc.expect(t, k, changed)
		})
	}
}

func TestKubeSecretProvider_set(t *testing.T) {
	tests := []struct {
		name   string
		synced bool
		expect func(t *testing.T, k *kubeSecretProvider, changed int)
	}{
		{
			name:   "report a secret that changed after the initial list",
			synced: true,
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Equal(1, changed)
				assert.Len(k.lookup(mockRegistryTarget), 1)
			},
		},
		{
			name:   "report no secret of the initial list",
			synced: false,
			expect: func(t *testing.T, k *kubeSecretProvider, changed int) {
				assert := assert.New(t)
				assert.Zero(changed)
				assert.Len(k.lookup(mockRegistryTarget), 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var changed int
			k := newTestKubeSecretProvider(tc.synced, &changed)
			k.set("a/y", &secret{name: "a/y", auths: map[string]authConfig{"registry.example.com": mockAuthConfig}})
			tc.expect(t, k, changed)
		})
	}
}

func TestKubeSecretProvider_transform(t *testing.T) {
	tests := []struct {
		name   string
		passes int
		secret func() *corev1.Secret
		expect func(t *testing.T, s *corev1.Secret)
	}{
		{
			name:   "keep the times of data owners only",
			passes: 1,
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
					assert.Same(dataOwnerFields, f.FieldsV1)
					assert.Equal(&mockUpdatedAt, f.Time)
				}
			},
		},
		{
			name:   "a manager of a label named data owns no data",
			passes: 1,
			secret: func() *corev1.Secret {
				s := newMockSecret("a", "y", "1", "registry.example.com", "a")
				s.ManagedFields = []metav1.ManagedFieldsEntry{
					{Manager: "creator", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data":{".":{}},"f:type":{}}`)}},
					{Manager: "labeler", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{"f:data":{}},"f:annotations":{"f:stringData":{}}}}`)}},
					{Manager: "broken", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data"`)}},
				}
				return s
			},
			expect: func(t *testing.T, s *corev1.Secret) {
				assert := assert.New(t)
				assert.Len(s.ManagedFields, 1)
				assert.Equal("creator", s.ManagedFields[0].Manager)
			},
		},
		{
			name:   "a second pass keeps the data owners",
			passes: 2,
			secret: func() *corev1.Secret {
				s := newMockSecret("a", "y", "1", "registry.example.com", "a")
				s.ManagedFields = []metav1.ManagedFieldsEntry{
					{Manager: "creator", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data":{".":{}},"f:type":{}}`)}},
					{Manager: "labeler", Time: &mockUpdatedAt, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{}}}`)}},
				}
				return s
			},
			expect: func(t *testing.T, s *corev1.Secret) {
				assert := assert.New(t)
				assert.Len(s.ManagedFields, 1)
				assert.Equal(mockUpdatedAt.Time, (&kubeSecretProvider{}).updatedAt(s))
			},
		},
		{
			name:   "drop the data of a secret without a docker config",
			passes: 1,
			secret: func() *corev1.Secret {
				s := newMockSecret("a", "y", "1", "registry.example.com", "a")
				s.Data = map[string][]byte{"extra": []byte("unread")}
				return s
			},
			expect: func(t *testing.T, s *corev1.Secret) {
				assert := assert.New(t)
				assert.Empty(s.Data)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var obj any = tc.secret()
			for range tc.passes {
				var err error
				obj, err = (&kubeSecretProvider{}).transform(obj)
				assert.NoError(t, err)
			}

			tc.expect(t, obj.(*corev1.Secret))
		})
	}
}

func TestKubeSecretProvider_ownsData(t *testing.T) {
	tests := []struct {
		name   string
		entry  metav1.ManagedFieldsEntry
		expect func(t *testing.T, owns bool)
	}{
		{
			name:  "owner of data",
			entry: metav1.ManagedFieldsEntry{FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data":{}}`)}},
			expect: func(t *testing.T, owns bool) {
				assert := assert.New(t)
				assert.True(owns)
			},
		},
		{
			name:  "owner of string data",
			entry: metav1.ManagedFieldsEntry{FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:stringData":{}}`)}},
			expect: func(t *testing.T, owns bool) {
				assert := assert.New(t)
				assert.True(owns)
			},
		},
		{
			name:  "owner of a label named data",
			entry: metav1.ManagedFieldsEntry{FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:labels":{"f:data":{}}}}`)}},
			expect: func(t *testing.T, owns bool) {
				assert := assert.New(t)
				assert.False(owns)
			},
		},
		{
			name:  "entry without a field set",
			entry: metav1.ManagedFieldsEntry{},
			expect: func(t *testing.T, owns bool) {
				assert := assert.New(t)
				assert.False(owns)
			},
		},
		{
			name:  "field set that does not decode",
			entry: metav1.ManagedFieldsEntry{FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:data":`)}},
			expect: func(t *testing.T, owns bool) {
				assert := assert.New(t)
				assert.False(owns)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, (&kubeSecretProvider{}).ownsData(tc.entry))
		})
	}
}

func TestNewKubeSecretProvider(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector string
		objects       func() []*corev1.Secret
		expect        func(t *testing.T, k *kubeSecretProvider, client *fake.Clientset, err error)
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
			expect: func(t *testing.T, k *kubeSecretProvider, client *fake.Clientset, err error) {
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
				assert.Same(dataOwnerFields, managedFields[0].FieldsV1)
				assert.NotNil(managedFields[0].Time)
			},
		},
		{
			name:          "secret updated after the initial list wins",
			labelSelector: "app=nydus",
			objects: func() []*corev1.Secret {
				return []*corev1.Secret{newMockSecret("a", "y", "1", "registry.example.com", "a")}
			},
			expect: func(t *testing.T, k *kubeSecretProvider, client *fake.Clientset, err error) {
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
			k, err := newKubeSecretProvider(client, tc.labelSelector, func() {})
			if err == nil {
				go k.informer.RunWithContext(ctx)
			}

			tc.expect(t, k, client, err)
		})
	}
}
