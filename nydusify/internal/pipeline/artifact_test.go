/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestValidateArtifactBlobMetas(t *testing.T) {
	dgst := digest.FromString("blob-a")
	metaName := dgst.Encoded() + ".blob.meta"
	desc := ocispec.Descriptor{Digest: dgst}

	tests := []struct {
		name      string
		descs     []ocispec.Descriptor
		metas     []nydus.BlobMetaFile
		wantError bool
	}{
		{
			name:  "matching descriptor and meta",
			descs: []ocispec.Descriptor{desc},
			metas: []nydus.BlobMetaFile{{Name: metaName}},
		},
		{
			name:      "missing meta",
			descs:     []ocispec.Descriptor{desc},
			wantError: true,
		},
		{
			name:      "unexpected meta",
			metas:     []nydus.BlobMetaFile{{Name: metaName}},
			wantError: true,
		},
		{
			name:      "mismatched meta",
			descs:     []ocispec.Descriptor{desc},
			metas:     []nydus.BlobMetaFile{{Name: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.blob.meta"}},
			wantError: true,
		},
		{
			name:      "duplicate descriptor",
			descs:     []ocispec.Descriptor{desc, desc},
			metas:     []nydus.BlobMetaFile{{Name: metaName}},
			wantError: true,
		},
		{
			name:      "duplicate meta",
			descs:     []ocispec.Descriptor{desc},
			metas:     []nydus.BlobMetaFile{{Name: metaName}, {Name: metaName}},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateArtifactBlobMetas(tt.descs, tt.metas)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateArtifactBlobMetas returned error: %v", err)
			}
		})
	}
}

func TestFilterArtifactBlobsForBootstrap(t *testing.T) {
	blobA := digest.FromString("blob-a")
	blobB := digest.FromString("blob-b")
	blobC := digest.FromString("blob-c")

	tests := []struct {
		name          string
		referenced    []digest.Digest
		descs         []ocispec.Descriptor
		metas         []nydus.BlobMetaFile
		externalBlobs []ExternalBlob
		wantDescs     []digest.Digest
		wantExternal  []digest.Digest
		wantError     bool
	}{
		{
			name:       "matching bootstrap and descriptors",
			referenced: []digest.Digest{blobA, blobB},
			descs:      []ocispec.Descriptor{{Digest: blobA}, {Digest: blobB}},
			metas: []nydus.BlobMetaFile{
				{Name: blobA.Encoded() + ".blob.meta"},
				{Name: blobB.Encoded() + ".blob.meta"},
			},
			wantDescs: []digest.Digest{blobA, blobB},
		},
		{
			name:       "missing descriptor for bootstrap blob",
			referenced: []digest.Digest{blobA, blobB},
			descs:      []ocispec.Descriptor{{Digest: blobA}},
			metas:      []nydus.BlobMetaFile{{Name: blobA.Encoded() + ".blob.meta"}},
			wantError:  true,
		},
		{
			name:       "extra descriptor is filtered",
			referenced: []digest.Digest{blobA},
			descs:      []ocispec.Descriptor{{Digest: blobA}, {Digest: blobC}},
			metas: []nydus.BlobMetaFile{
				{Name: blobA.Encoded() + ".blob.meta"},
				{Name: blobC.Encoded() + ".blob.meta"},
			},
			wantDescs: []digest.Digest{blobA},
		},
		{
			name:       "extra external descriptor is filtered",
			referenced: []digest.Digest{blobA},
			descs:      []ocispec.Descriptor{{Digest: blobA}, {Digest: blobC}},
			metas: []nydus.BlobMetaFile{
				{Name: blobA.Encoded() + ".blob.meta"},
				{Name: blobC.Encoded() + ".blob.meta"},
			},
			externalBlobs: []ExternalBlob{
				{Descriptor: ocispec.Descriptor{Digest: blobA}},
				{Descriptor: ocispec.Descriptor{Digest: blobC}},
			},
			wantDescs:    []digest.Digest{blobA},
			wantExternal: []digest.Digest{blobA},
		},
		{
			name:       "bootstrap with no device table keeps provided descriptors",
			referenced: nil,
			descs:      []ocispec.Descriptor{{Digest: blobA}},
			metas:      []nydus.BlobMetaFile{{Name: blobA.Encoded() + ".blob.meta"}},
			wantDescs:  []digest.Digest{blobA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			referenced := make(map[digest.Digest]struct{}, len(tt.referenced))
			for _, dgst := range tt.referenced {
				referenced[dgst] = struct{}{}
			}
			descs, metas, external, _, err := filterArtifactBlobsByReferences(
				referenced, tt.descs, tt.metas, tt.externalBlobs, nil,
			)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("filterArtifactBlobsForBootstrap returned error: %v", err)
			}
			if got := descriptorDigests(descs); !digestSlicesEqual(got, tt.wantDescs) {
				t.Fatalf("descriptors = %v, want %v", got, tt.wantDescs)
			}
			if got := blobMetaNames(metas); len(got) != len(tt.wantDescs) {
				t.Fatalf("metas = %v, want %d entries", got, len(tt.wantDescs))
			}
			if got := externalBlobDigests(external); !digestSlicesEqual(got, tt.wantExternal) {
				t.Fatalf("external blobs = %v, want %v", got, tt.wantExternal)
			}
		})
	}
}

func TestFilterArtifactBlobPaths(t *testing.T) {
	blobA := digest.FromString("blob-a")
	blobB := digest.FromString("blob-b")
	paths := []string{
		filepath.Join("somewhere", blobA.Encoded()),
		filepath.Join("somewhere", blobB.Encoded()),
		filepath.Join("somewhere", "legacy-name"),
	}

	filtered := filterArtifactBlobPaths(paths, map[digest.Digest]struct{}{blobA: {}})
	if len(filtered) != 2 || filtered[0] != paths[0] || filtered[1] != paths[2] {
		t.Fatalf("filtered paths = %v, want live digest path and legacy path", filtered)
	}
}

func TestDescribeArtifactBlobUsesDigestNameAndSidecar(t *testing.T) {
	dir := t.TempDir()
	dgst := digest.FromString("writer-produced-blob")
	path := filepath.Join(dir, dgst.Encoded())
	blobData := []byte("blob data is not read to derive the digest")
	metaData := []byte("writer sidecar")
	if err := os.WriteFile(path, blobData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".blob.meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}

	desc, meta, err := describeArtifactBlob(path)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != dgst || desc.Size != int64(len(blobData)) {
		t.Fatalf("descriptor = %+v, want digest %s and size %d", desc, dgst, len(blobData))
	}
	if meta.Name != dgst.Encoded()+".blob.meta" || string(meta.Data) != string(metaData) {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestDescribeArtifactBlobHashesLegacyName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-name")
	blobData := []byte("legacy blob")
	metaData := []byte("legacy sidecar")
	if err := os.WriteFile(path, blobData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".blob.meta", metaData, 0o600); err != nil {
		t.Fatal(err)
	}

	desc, _, err := describeArtifactBlob(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := digest.FromBytes(blobData); desc.Digest != want {
		t.Fatalf("digest = %s, want %s", desc.Digest, want)
	}
}

func descriptorDigests(descs []ocispec.Descriptor) []digest.Digest {
	out := make([]digest.Digest, 0, len(descs))
	for _, desc := range descs {
		out = append(out, desc.Digest)
	}
	return out
}

func externalBlobDigests(blobs []ExternalBlob) []digest.Digest {
	out := make([]digest.Digest, 0, len(blobs))
	for _, blob := range blobs {
		out = append(out, blob.Descriptor.Digest)
	}
	return out
}

func blobMetaNames(metas []nydus.BlobMetaFile) []string {
	out := make([]string, 0, len(metas))
	for _, meta := range metas {
		out = append(out, meta.Name)
	}
	return out
}

func digestSlicesEqual(left, right []digest.Digest) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
