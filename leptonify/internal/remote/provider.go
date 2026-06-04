/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Provider pulls and pushes images through a local content store, using a
// docker registry resolver for remote access.
type Provider struct {
	store      content.Store
	platformMC platforms.MatchComparer
	insecure   bool
	plainHTTP  bool
	credFunc   CredentialFunc
}

// Options configures a Provider.
type Options struct {
	// WorkDir is the directory backing the local content store.
	WorkDir string
	// Insecure skips TLS certificate verification.
	Insecure bool
	// PlainHTTP uses HTTP instead of HTTPS to talk to the registry.
	PlainHTTP bool
	// PlatformMC selects which platforms to pull/push. Defaults to all.
	PlatformMC platforms.MatchComparer
}

// NewProvider creates a Provider backed by a local content store at
// opts.WorkDir.
func NewProvider(opts Options) (*Provider, error) {
	// Back the store with an in-memory label store so that content labels
	// (distribution source labels, gc references written during conversion)
	// can be set. local.NewStore alone returns an immutable store that rejects
	// label updates.
	store, err := local.NewLabeledStore(opts.WorkDir, newMemoryLabelStore())
	if err != nil {
		return nil, errors.Wrapf(err, "create local content store at %q", opts.WorkDir)
	}
	platformMC := opts.PlatformMC
	if platformMC == nil {
		platformMC = platforms.All
	}
	return &Provider{
		store:      store,
		platformMC: platformMC,
		insecure:   opts.Insecure,
		plainHTTP:  opts.PlainHTTP,
		credFunc:   NewDockerConfigCredFunc(),
	}, nil
}

// ContentStore returns the underlying local content store.
func (p *Provider) ContentStore() content.Store {
	return p.store
}

// PlatformMC returns the platform matcher used for pull/push and conversion.
func (p *Provider) PlatformMC() platforms.MatchComparer {
	return p.platformMC
}

func (p *Provider) resolver() remotes.Resolver {
	return NewResolver(p.insecure, p.plainHTTP, p.credFunc)
}

// Pull fetches ref (and all matched-platform content) into the local content
// store and returns the resolved root descriptor.
func (p *Provider) Pull(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	normalized, err := normalizeRef(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return fetch(ctx, p.store, p.resolver(), normalized, p.platformMC)
}

// Push uploads desc and all of its referenced content from the local store to
// ref.
func (p *Provider) Push(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	normalized, err := normalizeRef(ref)
	if err != nil {
		return err
	}
	return push(ctx, p.store, p.resolver(), desc, normalized, p.platformMC)
}

// normalizeRef expands shorthand image references to fully-qualified names so
// that Docker Hub shortcuts ("mariadb") and untagged references ("repo/img")
// resolve correctly. For example:
//
//	mariadb                 -> docker.io/library/mariadb:latest
//	user/img                -> docker.io/user/img:latest
//	localhost:5000/img      -> localhost:5000/img:latest
//	registry/img@sha256:... -> registry/img@sha256:... (unchanged)
func normalizeRef(ref string) (string, error) {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return "", errors.Wrapf(err, "parse reference %q", ref)
	}
	named = reference.TagNameOnly(named)
	return named.String(), nil
}

// memoryLabelStore is an in-memory implementation of local.LabelStore, allowing
// the local content store to persist content labels for the lifetime of the
// process.
type memoryLabelStore struct {
	mu     sync.Mutex
	labels map[digest.Digest]map[string]string
}

func newMemoryLabelStore() *memoryLabelStore {
	return &memoryLabelStore{labels: make(map[digest.Digest]map[string]string)}
}

func (s *memoryLabelStore) Get(d digest.Digest) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyLabels(s.labels[d]), nil
}

func (s *memoryLabelStore) Set(d digest.Digest, labels map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels[d] = copyLabels(labels)
	return nil
}

func (s *memoryLabelStore) Update(d digest.Digest, update map[string]string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	labels := s.labels[d]
	if labels == nil {
		labels = make(map[string]string)
	}
	for k, v := range update {
		if v == "" {
			delete(labels, k)
		} else {
			labels[k] = v
		}
	}
	s.labels[d] = labels
	return copyLabels(labels), nil
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
