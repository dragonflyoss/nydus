/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"bytes"
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

// kubeSecret is the credential source of kubernetes.io/dockerconfigjson
// secrets in every namespace.
type kubeSecret struct {
	// informer watches the secrets.
	informer cache.SharedIndexInformer

	// synced reports whether the handler received the initial list.
	synced cache.InformerSynced

	// onChange receives the registry keys of a changed secret, once lookups
	// see the change.
	onChange func(keys []string)

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

// New secret source, whose informer starts with informer.RunWithContext. The
// label selector is validated by config. onChange is called from the
// informer's handler goroutine.
func newKubeSecret(client kubernetes.Interface, labelSelector string, onChange func(keys []string)) (*kubeSecret, error) {
	k := &kubeSecret{
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
		AddFunc:    k.store,
		UpdateFunc: k.update,
		DeleteFunc: k.delete,
	})
	if err != nil {
		return nil, fmt.Errorf("add secret event handler: %w", err)
	}

	k.synced = registration.HasSynced
	return k, nil
}

// transform drops what a lookup never reads from a cached secret: data keys
// other than .dockerconfigjson, managedFields entries that own no data, so a
// label edit never makes a secret newest, the field sets of the rest, whose
// times tell when the data changed, and annotations, which may hold a
// last-applied copy of the data.
func (k *kubeSecret) transform(obj any) (any, error) {
	if s, ok := obj.(*corev1.Secret); ok {
		if data, ok := s.Data[corev1.DockerConfigJsonKey]; ok {
			s.Data = map[string][]byte{corev1.DockerConfigJsonKey: data}
		} else {
			s.Data = nil
		}

		s.ManagedFields = slices.DeleteFunc(s.ManagedFields, func(f metav1.ManagedFieldsEntry) bool {
			return f.FieldsV1 == nil || (!bytes.Contains(f.FieldsV1.Raw, []byte(`"f:data"`)) && !bytes.Contains(f.FieldsV1.Raw, []byte(`"f:stringData"`)))
		})

		for i := range s.ManagedFields {
			s.ManagedFields[i].FieldsV1 = nil
		}

		s.Annotations = nil
	}

	return obj, nil
}

// update stores an updated secret, skipping relists of an unchanged one.
func (k *kubeSecret) update(oldObj, newObj any) {
	oldSecret, ok := oldObj.(*corev1.Secret)
	if !ok {
		return
	}

	newSecret, ok := newObj.(*corev1.Secret)
	if !ok || oldSecret.ResourceVersion == newSecret.ResourceVersion {
		return
	}

	k.store(newObj)
}

// delete forgets a deleted secret.
func (k *kubeSecret) delete(obj any) {
	name, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		log.L.WithError(err).Warn("skip deleted secret without a name")
		return
	}

	k.set(name, nil)
}

// store parses a secret and stores it, or forgets it when malformed.
func (k *kubeSecret) store(obj any) {
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
func (k *kubeSecret) updatedAt(s *corev1.Secret) time.Time {
	updatedAt := s.CreationTimestamp.Time
	for _, f := range s.ManagedFields {
		if f.Time != nil && f.Time.After(updatedAt) {
			updatedAt = f.Time.Time
		}
	}

	return updatedAt
}

// set replaces the secret of a namespace/name, nil to forget it, and passes
// the registry keys it had and has to onChange.
func (k *kubeSecret) set(name string, s *secret) {
	k.mu.Lock()
	old := k.secrets[name]
	if s == nil {
		delete(k.secrets, name)
	} else {
		k.secrets[name] = s
	}

	k.keyring = nil
	k.mu.Unlock()

	var keys []string
	for _, changed := range []*secret{old, s} {
		if changed == nil {
			continue
		}

		for addr := range changed.auths {
			if key, err := registryKey(addr); err == nil {
				keys = append(keys, key)
			}
		}
	}

	if len(keys) > 0 {
		k.onChange(keys)
	}
}

// lookup returns the credentials matching target. Among equal keys, the
// secret updated last comes first, ties in namespace/name order.
func (k *kubeSecret) lookup(target string) []credential {
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
