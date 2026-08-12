// Package oci reads and writes OCI image structures (manifests, indexes,
// configs, layer blobs) in a containerd content store.
package oci

import (
	"context"
	"encoding/json"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// ResolveManifest returns the manifest descriptor for the requested platform.
// If rootDesc is already a manifest it is returned as-is; an index is resolved
// to its most specific matching manifest entry, skipping non-manifest entries
// such as attestations.
func ResolveManifest(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (ocispec.Descriptor, error) {
	if images.IsManifestType(rootDesc.MediaType) {
		return rootDesc, nil
	}

	if !images.IsIndexType(rootDesc.MediaType) {
		return ocispec.Descriptor{}, errors.Errorf("unsupported root media type %q", rootDesc.MediaType)
	}

	var index ocispec.Index
	if err := ReadJSON(ctx, cs, rootDesc, &index); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "read index")
	}

	if len(index.Manifests) == 0 {
		return ocispec.Descriptor{}, errors.New("image index has no manifests")
	}

	var candidates []ocispec.Descriptor
	for _, m := range index.Manifests {
		if !images.IsManifestType(m.MediaType) {
			continue
		}

		if m.Platform == nil || platformMC.Match(*m.Platform) {
			candidates = append(candidates, m)
		}
	}

	if len(candidates) == 0 {
		return ocispec.Descriptor{}, errors.New("no manifest matches the requested platform")
	}

	// Prefer the platform the matcher considers most specific.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.Platform != nil && best.Platform != nil && platformMC.Less(*c.Platform, *best.Platform) {
			best = c
		}
	}

	return best, nil
}

// ReadJSON reads desc from cs and unmarshals it into v.
func ReadJSON(ctx context.Context, cs content.Store, desc ocispec.Descriptor, v any) error {
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return errors.Wrapf(err, "read blob %s", desc.Digest)
	}

	if err := json.Unmarshal(b, v); err != nil {
		return errors.Wrapf(err, "unmarshal %s", desc.Digest)
	}

	return nil
}

// Labels returns the content-store labels of the blob at dgst. The result is
// never nil, so callers can extend it without a nil check.
func Labels(ctx context.Context, cs content.Store, dgst digest.Digest) (map[string]string, error) {
	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return nil, errors.Wrapf(err, "stat content %s", dgst)
	}

	if info.Labels == nil {
		return map[string]string{}, nil
	}

	return info.Labels, nil
}
