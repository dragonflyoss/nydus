/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/containerd/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// dataOwnerFields replaces the field set of a cached managedFields entry that
// owns the secret's data: small, shared by every cached secret, and still a
// data owner when transform sees the secret again.
var dataOwnerFields = &metav1.FieldsV1{Raw: []byte(`{"f:data":{}}`)}

// kubeSecretProvider provides the credentials of the
// kubernetes.io/dockerconfigjson secrets of every namespace.
type kubeSecretProvider struct {
	// informer watches the secrets.
	informer cache.SharedIndexInformer

	// synced reports whether the handler received the initial list.
	synced cache.InformerSynced

	// onChange is called for a secret that changed after the initial list,
	// once lookups see the change.
	onChange func()

	// mu guards secrets and keyring.
	mu sync.Mutex

	// secrets holds the parsed secrets by namespace/name.
	secrets map[string]*secret

	// keyring indexes secrets, nil until a lookup rebuilds it.
	keyring *keyring
}

// secret is a parsed dockerconfigjson secret.
type secret struct {
	// name is the secret's namespace/name.
	name string

	// updatedAt is when the secret last changed.
	updatedAt time.Time

	// auths holds the credentials by registry.
	auths map[string]authConfig
}

// newKubeSecretProvider returns a provider whose informer starts with
// informer.RunWithContext. The label selector is validated by config.
// onChange is called from the informer's handler goroutine.
func newKubeSecretProvider(client kubernetes.Interface, labelSelector string, onChange func()) (*kubeSecretProvider, error) {
	k := &kubeSecretProvider{
		onChange: onChange,
		secrets:  make(map[string]*secret),
	}

	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("type", string(corev1.SecretTypeDockerConfigJson)).String()
			options.LabelSelector = labelSelector
		}),
		informers.WithTransform(k.transform),
	)
	k.informer = factory.Core().V1().Secrets().Informer()

	registration, err := k.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    k.add,
		UpdateFunc: k.update,
		DeleteFunc: k.delete,
	})
	if err != nil {
		return nil, fmt.Errorf("add secret event handler: %w", err)
	}

	k.synced = registration.HasSynced
	return k, nil
}

// ownsData reports whether a managedFields entry owns the secret's data: its
// field set has data or stringData at the top level, not a label or an
// annotation of that name.
func (k *kubeSecretProvider) ownsData(entry metav1.ManagedFieldsEntry) bool {
	if entry.FieldsV1 == nil {
		return false
	}

	var owned map[string]json.RawMessage
	if err := json.Unmarshal(entry.FieldsV1.Raw, &owned); err != nil {
		return false
	}

	_, data := owned["f:data"]
	_, stringData := owned["f:stringData"]
	return data || stringData
}

// transform drops what a lookup never reads from a secret before it is
// cached:
//   - data keys other than .dockerconfigjson;
//   - managedFields entries that own no data, so a label edit never makes a
//     secret the newest;
//   - the field sets of the remaining entries, whose times alone tell when the
//     data changed;
//   - annotations, which may hold a last-applied copy of the data.
//
// It is idempotent, as client-go asks of a transform, refer to
// https://github.com/kubernetes/client-go/blob/master/tools/cache/delta_fifo.go.
func (k *kubeSecretProvider) transform(obj any) (any, error) {
	s, ok := obj.(*corev1.Secret)
	if !ok {
		return obj, nil
	}

	if data, ok := s.Data[corev1.DockerConfigJsonKey]; ok {
		s.Data = map[string][]byte{corev1.DockerConfigJsonKey: data}
	} else {
		s.Data = nil
	}

	s.ManagedFields = slices.DeleteFunc(s.ManagedFields, func(f metav1.ManagedFieldsEntry) bool {
		return !k.ownsData(f)
	})

	for i := range s.ManagedFields {
		s.ManagedFields[i].FieldsV1 = dataOwnerFields
	}

	s.Annotations = nil
	return s, nil
}

// update adds an updated secret, skipping relists of an unchanged one.
func (k *kubeSecretProvider) update(oldObj, newObj any) {
	oldSecret, ok := oldObj.(*corev1.Secret)
	if !ok {
		return
	}

	newSecret, ok := newObj.(*corev1.Secret)
	if !ok || oldSecret.ResourceVersion == newSecret.ResourceVersion {
		return
	}

	k.add(newObj)
}

// delete forgets a deleted secret.
func (k *kubeSecretProvider) delete(obj any) {
	name, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		log.L.WithError(err).Warn("skip deleted secret without a name")
		return
	}

	k.set(name, nil)
}

// add parses a secret and keeps it, or forgets it when malformed.
func (k *kubeSecretProvider) add(obj any) {
	s, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	name := s.Namespace + "/" + s.Name
	data, ok := s.Data[corev1.DockerConfigJsonKey]
	if !ok || s.Type != corev1.SecretTypeDockerConfigJson {
		log.L.WithFields(log.Fields{"secret": name, "key": corev1.DockerConfigJsonKey}).Warn("skip secret without key")
		k.set(name, nil)
		return
	}

	// Decode every secret into its own config and skip a malformed one;
	// go-containerregistry reuses one config across secrets, multiplying
	// entries, and fails the whole keyring on one bad secret.
	var cfg dockerConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.L.WithError(err).WithField("secret", name).Warn("skip malformed secret")
		k.set(name, nil)
		return
	}

	k.set(name, &secret{name: name, updatedAt: k.updatedAt(s), auths: cfg.Auths})
}

// updatedAt returns when a secret last changed: the newest time of its
// managedFields, which unlike event order survives a restart, or its creation
// when no manager tracks it.
func (k *kubeSecretProvider) updatedAt(s *corev1.Secret) time.Time {
	updatedAt := s.CreationTimestamp.Time
	for _, f := range s.ManagedFields {
		if f.Time != nil && f.Time.After(updatedAt) {
			updatedAt = f.Time.Time
		}
	}

	return updatedAt
}

// set replaces the secret of a namespace/name, nil to forget it, and calls
// onChange. The secrets of the initial list are reported together once it is
// complete, by whoever waits for synced.
func (k *kubeSecretProvider) set(name string, s *secret) {
	k.mu.Lock()
	if s == nil {
		delete(k.secrets, name)
	} else {
		k.secrets[name] = s
	}

	k.keyring = nil
	k.mu.Unlock()

	if k.synced() {
		k.onChange()
	}
}

// lookup returns the credentials matching target. Among equal keys, the
// secret updated last comes first, ties in namespace/name order.
func (k *kubeSecretProvider) lookup(target registryKey) []credential {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.keyring == nil {
		secrets := slices.SortedFunc(maps.Values(k.secrets), func(a, b *secret) int {
			if c := b.updatedAt.Compare(a.updatedAt); c != 0 {
				return c
			}

			return strings.Compare(a.name, b.name)
		})

		k.keyring = &keyring{}
		for _, s := range secrets {
			k.keyring.add("secret "+s.name, s.auths)
		}
	}

	return k.keyring.lookup(target)
}
