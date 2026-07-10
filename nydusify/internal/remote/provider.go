/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
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

// Registry identifies which side's TLS/HTTP settings apply: the source
// registry (images are pulled from) or the target registry (images are pushed
// to). The two sides may live on different registries with different security
// requirements.
type Registry int

const (
	// Source selects the source registry settings (used by pulls).
	Source Registry = iota
	// Target selects the target registry settings (used by pushes).
	Target
)

// Provider pulls and pushes images through a local content store, using a
// docker registry resolver for remote access.
type Provider struct {
	store           content.Store
	platformMC      platforms.MatchComparer
	sourceInsecure  bool
	sourcePlainHTTP bool
	targetInsecure  bool
	targetPlainHTTP bool
	credFunc        CredentialFunc
}

// Options configures a Provider.
type Options struct {
	// WorkDir is the directory backing the local content store.
	WorkDir string
	// SourceInsecure skips TLS certificate verification for the source registry.
	SourceInsecure bool
	// SourcePlainHTTP uses HTTP instead of HTTPS for the source registry.
	SourcePlainHTTP bool
	// TargetInsecure skips TLS certificate verification for the target registry.
	TargetInsecure bool
	// TargetPlainHTTP uses HTTP instead of HTTPS for the target registry.
	TargetPlainHTTP bool
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
		store:           store,
		platformMC:      platformMC,
		sourceInsecure:  opts.SourceInsecure,
		sourcePlainHTTP: opts.SourcePlainHTTP,
		targetInsecure:  opts.TargetInsecure,
		targetPlainHTTP: opts.TargetPlainHTTP,
		credFunc:        NewDockerConfigCredFunc(),
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

// Insecure reports whether TLS certificate verification is skipped for the
// given registry side.
func (p *Provider) Insecure(reg Registry) bool {
	if reg == Target {
		return p.targetInsecure
	}
	return p.sourceInsecure
}

// PlainHTTP reports whether plain HTTP is used to talk to the given registry
// side.
func (p *Provider) PlainHTTP(reg Registry) bool {
	if reg == Target {
		return p.targetPlainHTTP
	}
	return p.sourcePlainHTTP
}

// Credentials resolves the username and password for a registry host using the
// provider's credential function.
func (p *Provider) Credentials(host string) (string, string, error) {
	return p.credFunc(host)
}

func (p *Provider) resolver(reg Registry) remotes.Resolver {
	return NewResolver(p.Insecure(reg), p.PlainHTTP(reg), p.credFunc)
}

// PullOptions controls which data layers Pull downloads. Index, manifest and
// config descriptors and the nydus bootstrap layer are always pulled.
type PullOptions struct {
	// PullOCILayers downloads plain OCI data layers. Disable it when no
	// filesystem extraction/diff is needed.
	PullOCILayers bool
	// PullNydusBlobs downloads nydus data blob layers. Disable it when blobs
	// are fetched on demand (FUSE) or not needed (static bootstrap check).
	PullNydusBlobs bool
}

// PullAll downloads every data layer (OCI layers and nydus blobs), matching
// the original full-pull behavior.
var PullAll = PullOptions{PullOCILayers: true, PullNydusBlobs: true}

// Pull fetches ref into the local content store and returns the resolved root
// descriptor. opts selects which data layers are downloaded. reg selects which
// registry side's TLS/HTTP settings to use; pulls normally use Source, except
// when re-reading an already-pushed target image.
func (p *Provider) Pull(ctx context.Context, ref string, opts PullOptions, reg Registry) (ocispec.Descriptor, error) {
	normalized, err := normalizeRef(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return fetch(ctx, p.store, p.resolver(reg), normalized, p.platformMC, opts)
}

// Push uploads desc and all of its referenced content from the local store to
// ref, using the target registry settings.
func (p *Provider) Push(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	normalized, err := normalizeRef(ref)
	if err != nil {
		return err
	}
	return push(ctx, p.store, p.resolver(Target), desc, normalized, p.platformMC)
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
