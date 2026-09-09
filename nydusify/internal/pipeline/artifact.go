/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"archive/tar"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// ArtifactOption configures packaging existing nydus runtime artifacts into an
// OCI nydus image manifest. It is intended for images produced outside
// nydusify, such as an incremental writer that already emitted image.boot and
// the full blob files referenced by that bootstrap.
type ArtifactOption struct {
	// BuilderPath is the nydus binary used to inspect the bootstrap metadata.
	BuilderPath string
	// BootstrapPath is the writer-produced nydus bootstrap to pack as
	// image/image.boot in the bootstrap layer.
	BootstrapPath string
	// BlobPaths are full nydus blob files to include in the manifest. Paths may
	// be in any order; when BlobDir is also set, both sets are included.
	BlobPaths []string
	// BlobDir, when set, contributes every regular file whose basename is a
	// lowercase sha256 hex digest. This matches nydus blob cache directories that
	// store blobs by digest.
	BlobDir string
	// ParentImages are already-pulled nydus images whose data blobs are reused by
	// descriptor only. Their data blobs are not read from the local content store.
	ParentImages []ParentImageMetadata
	// AppendInBootstrap lists local files to bundle into the bootstrap layer tar
	// alongside image.boot and blob meta artifacts.
	AppendInBootstrap []string
	// Platform is the single platform the output manifest targets.
	Platform ocispec.Platform
}

// ParentImageMetadata is the metadata required to reuse an existing nydus image
// as the lower part of an artifact image without downloading its data blobs.
type ParentImageMetadata struct {
	Ref       string
	Blobs     []ocispec.Descriptor
	BlobMetas []nydus.BlobMetaFile
	Config    json.RawMessage
}

// ExternalBlob records a blob descriptor that the output manifest references
// but does not have in the local content store.
type ExternalBlob struct {
	SourceRef  string
	Descriptor ocispec.Descriptor
}

// ConvertNydusArtifacts packages an existing nydus bootstrap and full blob
// files into an OCI nydus image rooted at a single manifest descriptor. The
// returned external blobs must already exist, or be mounted, in the target
// repository before pushing with a content-store skip handler.
func ConvertNydusArtifacts(ctx context.Context, cs content.Store, opt ArtifactOption) (*ocispec.Descriptor, []ExternalBlob, error) {
	if opt.BootstrapPath == "" {
		return nil, nil, errors.New("--bootstrap is required when packaging nydus artifacts")
	}
	if opt.Platform.OS == "" {
		opt.Platform = platforms.DefaultSpec()
	}

	bootstrapData, err := os.ReadFile(opt.BootstrapPath)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "read bootstrap %q", opt.BootstrapPath)
	}
	appendFiles, err := validateAndReadAppendFiles(opt.AppendInBootstrap)
	if err != nil {
		return nil, nil, err
	}
	blobPaths, err := collectArtifactBlobPaths(opt.BlobPaths, opt.BlobDir)
	if err != nil {
		return nil, nil, err
	}
	if len(blobPaths) == 0 && len(opt.ParentImages) == 0 {
		return nil, nil, errors.New("at least one --blob/--blob-dir or --parent-image is required")
	}
	if len(opt.ParentImages) > 1 {
		return nil, nil, errors.New("only one --parent-image is supported")
	}

	blobDescs := make([]ocispec.Descriptor, 0, len(blobPaths))
	blobMetas := make([]nydus.BlobMetaFile, 0, len(blobPaths))
	externalBlobs := make([]ExternalBlob, 0)
	var baseConfig json.RawMessage
	for _, parent := range opt.ParentImages {
		blobDescs = append(blobDescs, parent.Blobs...)
		blobMetas = append(blobMetas, parent.BlobMetas...)
		for _, desc := range parent.Blobs {
			externalBlobs = append(externalBlobs, ExternalBlob{SourceRef: parent.Ref, Descriptor: desc})
		}
		if len(parent.Config) > 0 {
			baseConfig = parent.Config
		}
	}

	for _, path := range blobPaths {
		desc, meta, err := ingestArtifactBlob(ctx, cs, path)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "ingest blob %q", path)
		}
		blobDescs = append(blobDescs, desc)
		blobMetas = append(blobMetas, meta)
	}
	blobDescs, blobMetas, externalBlobs, err = filterArtifactBlobsForBootstrap(ctx, opt.BuilderPath, opt.BootstrapPath, blobDescs, blobMetas, externalBlobs)
	if err != nil {
		return nil, nil, err
	}
	if err := validateArtifactBlobMetas(blobDescs, blobMetas); err != nil {
		return nil, nil, err
	}

	bootstrapDesc, err := oci.WriteBootstrapLayer(ctx, cs, bootstrapData, blobMetas, appendFiles)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write bootstrap layer")
	}

	layers := make([]ocispec.Descriptor, 0, len(blobDescs)+1)
	layers = append(layers, blobDescs...)
	layers = append(layers, *bootstrapDesc)

	diffIDs := make([]digest.Digest, 0, len(layers))
	history := make([]ocispec.History, 0, len(layers))
	for _, l := range blobDescs {
		diffID, err := layerDiffID(l)
		if err != nil {
			return nil, nil, err
		}
		diffIDs = append(diffIDs, diffID)
		history = append(history, ocispec.History{CreatedBy: "Nydus Artifact", Comment: "Nydus Data Layer"})
	}
	bootstrapDiffID, err := layerDiffID(*bootstrapDesc)
	if err != nil {
		return nil, nil, err
	}
	diffIDs = append(diffIDs, bootstrapDiffID)
	history = append(history, ocispec.History{CreatedBy: "Nydus Converter", Comment: "Nydus Bootstrap Layer"})

	configJSON, err := buildImageConfig(baseConfig, opt.Platform, diffIDs, history)
	if err != nil {
		return nil, nil, errors.Wrap(err, "build image config")
	}
	configDesc, err := oci.WriteJSON(ctx, cs, configJSON, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write image config")
	}
	configDesc.MediaType = ocispec.MediaTypeImageConfig

	labels := map[string]string{"containerd.io/gc.ref.content.config": configDesc.Digest.String()}
	for idx, l := range layers {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", idx)] = l.Digest.String()
	}
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    *configDesc,
		Layers:    layers,
	}
	manifestDesc, err := oci.WriteJSON(ctx, cs, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, labels)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write manifest")
	}
	return manifestDesc, externalBlobs, nil
}

// LoadParentNydusArtifact reads only the manifest/config/bootstrap metadata of
// a pulled parent nydus image. The parent's data blobs may be absent locally.
func LoadParentNydusArtifact(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer, ref string) (ParentImageMetadata, error) {
	manifestDesc, err := oci.ResolveManifest(ctx, cs, rootDesc, platformMC)
	if err != nil {
		return ParentImageMetadata{}, err
	}
	var manifest ocispec.Manifest
	if err := oci.ReadJSON(ctx, cs, manifestDesc, &manifest); err != nil {
		return ParentImageMetadata{}, errors.Wrap(err, "read parent manifest")
	}
	blobs, bootstrap, optimized, err := nydus.SplitLayers(manifest.Layers)
	if err != nil {
		return ParentImageMetadata{}, err
	}
	if optimized != nil {
		return ParentImageMetadata{}, errors.New("--parent-image does not support optimized nydus blob layers")
	}
	if bootstrap == nil {
		return ParentImageMetadata{}, errors.New("parent image has no nydus bootstrap layer")
	}
	metas, err := readBootstrapBlobMetas(ctx, cs, *bootstrap)
	if err != nil {
		return ParentImageMetadata{}, err
	}
	var config json.RawMessage
	if err := oci.ReadJSON(ctx, cs, manifest.Config, &config); err != nil {
		return ParentImageMetadata{}, errors.Wrap(err, "read parent config")
	}
	return ParentImageMetadata{Ref: ref, Blobs: blobs, BlobMetas: metas, Config: config}, nil
}

func readBootstrapBlobMetas(ctx context.Context, cs content.Store, desc ocispec.Descriptor) ([]nydus.BlobMetaFile, error) {
	decompressed, err := oci.OpenDecompressedBlob(ctx, cs, desc)
	if err != nil {
		return nil, errors.Wrap(err, "open parent bootstrap layer")
	}
	defer func() { _ = decompressed.Close() }()

	var metas []nydus.BlobMetaFile
	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "read parent bootstrap tar")
		}
		if !strings.HasSuffix(hdr.Name, ".blob.meta") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, errors.Wrapf(err, "read parent blob meta %s", hdr.Name)
		}
		metas = append(metas, nydus.BlobMetaFile{Name: filepath.Base(hdr.Name), Data: data})
	}
	if len(metas) == 0 {
		return nil, errors.New("parent bootstrap layer has no blob meta files")
	}
	return metas, nil
}

func validateArtifactBlobMetas(blobDescs []ocispec.Descriptor, blobMetas []nydus.BlobMetaFile) error {
	expected := make(map[string]struct{}, len(blobDescs))
	for _, desc := range blobDescs {
		if desc.Digest.Algorithm() != digest.SHA256 {
			return errors.Errorf("nydus blob layer %s is not a sha256 digest", desc.Digest)
		}
		name := desc.Digest.Encoded() + ".blob.meta"
		if _, ok := expected[name]; ok {
			return errors.Errorf("duplicate nydus blob layer %s", desc.Digest)
		}
		expected[name] = struct{}{}
	}

	seen := make(map[string]struct{}, len(blobMetas))
	for _, meta := range blobMetas {
		if _, ok := seen[meta.Name]; ok {
			return errors.Errorf("duplicate blob meta %q", meta.Name)
		}
		seen[meta.Name] = struct{}{}
		if _, ok := expected[meta.Name]; !ok {
			return errors.Errorf("blob meta %q does not match any nydus blob layer", meta.Name)
		}
	}
	for name := range expected {
		if _, ok := seen[name]; !ok {
			return errors.Errorf("missing blob meta %q", name)
		}
	}
	return nil
}

func filterArtifactBlobsForBootstrap(
	ctx context.Context,
	builderPath string,
	bootstrapPath string,
	blobDescs []ocispec.Descriptor,
	blobMetas []nydus.BlobMetaFile,
	externalBlobs []ExternalBlob,
) ([]ocispec.Descriptor, []nydus.BlobMetaFile, []ExternalBlob, error) {
	referenced, err := inspectBootstrapBlobDigests(ctx, builderPath, bootstrapPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(referenced) == 0 {
		return blobDescs, blobMetas, externalBlobs, nil
	}

	provided := make(map[digest.Digest]struct{}, len(blobDescs))
	for _, desc := range blobDescs {
		provided[desc.Digest] = struct{}{}
	}
	for dgst := range referenced {
		if _, ok := provided[dgst]; !ok {
			return nil, nil, nil, errors.Errorf("bootstrap references missing nydus blob %s; pass it with --blob/--blob-dir or include it through --parent-image", dgst)
		}
	}

	filteredDescs := blobDescs[:0]
	for _, desc := range blobDescs {
		if _, ok := referenced[desc.Digest]; ok {
			filteredDescs = append(filteredDescs, desc)
		}
	}

	filteredMetas := blobMetas[:0]
	for _, meta := range blobMetas {
		dgst, ok := blobMetaDigest(meta.Name)
		if ok {
			if _, referenced := referenced[dgst]; referenced {
				filteredMetas = append(filteredMetas, meta)
			}
		}
	}

	filteredExternal := externalBlobs[:0]
	for _, blob := range externalBlobs {
		if _, ok := referenced[blob.Descriptor.Digest]; ok {
			filteredExternal = append(filteredExternal, blob)
		}
	}
	return filteredDescs, filteredMetas, filteredExternal, nil
}

var inspectBootstrapBlobDigests = bootstrapBlobDigestsFromNydusCheck

type bootstrapCheckReport struct {
	Blobs []struct {
		SlotSHA256 string `json:"slot_sha256"`
	} `json:"blobs"`
}

func bootstrapBlobDigestsFromNydusCheck(ctx context.Context, builderPath string, bootstrapPath string) (map[digest.Digest]struct{}, error) {
	cmd := exec.CommandContext(ctx, cmp.Or(builderPath, nydus.DefaultBuilder), "check", "--bootstrap", bootstrapPath, "--output", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Errorf("inspect bootstrap %q with nydus check: %v: %s", bootstrapPath, err, strings.TrimSpace(string(out)))
	}

	var report bootstrapCheckReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, errors.Wrap(err, "parse nydus check json output")
	}
	referenced := make(map[digest.Digest]struct{}, len(report.Blobs))
	for index, blob := range report.Blobs {
		dgst, err := digest.Parse("sha256:" + blob.SlotSHA256)
		if err != nil || dgst.Algorithm() != digest.SHA256 {
			return nil, errors.Errorf("nydus check blob %d has invalid sha256 %q", index+1, blob.SlotSHA256)
		}
		referenced[dgst] = struct{}{}
	}
	return referenced, nil
}

func blobMetaDigest(name string) (digest.Digest, bool) {
	encoded, ok := strings.CutSuffix(name, ".blob.meta")
	if !ok {
		return "", false
	}
	dgst, err := digest.Parse("sha256:" + encoded)
	return dgst, err == nil && dgst.Algorithm() == digest.SHA256
}

func layerDiffID(desc ocispec.Descriptor) (digest.Digest, error) {
	if desc.Annotations == nil || desc.Annotations[nydus.LayerAnnotationUncompressed] == "" {
		return "", errors.Errorf("layer %s missing %s annotation", desc.Digest, nydus.LayerAnnotationUncompressed)
	}
	return digest.Digest(desc.Annotations[nydus.LayerAnnotationUncompressed]), nil
}

func collectArtifactBlobPaths(paths []string, dir string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	add := func(path string) error {
		if path == "" {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return errors.Wrapf(err, "stat blob %q", path)
		}
		if info.IsDir() {
			return errors.Errorf("blob path %q is a directory", path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return errors.Wrapf(err, "resolve blob %q", path)
		}
		if _, ok := seen[abs]; ok {
			return nil
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
		return nil
	}

	for _, path := range paths {
		if err := add(path); err != nil {
			return nil, err
		}
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, errors.Wrapf(err, "read blob dir %q", dir)
		}
		var names []string
		for _, entry := range entries {
			if entry.Type().IsRegular() && isSha256Hex(entry.Name()) {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if err := add(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func ingestArtifactBlob(ctx context.Context, cs content.Store, path string) (ocispec.Descriptor, nydus.BlobMetaFile, error) {
	desc, err := oci.IngestBlobFile(ctx, cs, path, "")
	if err != nil {
		return ocispec.Descriptor{}, nydus.BlobMetaFile{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, nydus.BlobMetaFile{}, errors.Wrap(err, "open blob for metadata")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return ocispec.Descriptor{}, nydus.BlobMetaFile{}, errors.Wrap(err, "stat blob for metadata")
	}
	meta, err := nydus.ExtractBlobMeta(f, info.Size())
	if err != nil {
		return ocispec.Descriptor{}, nydus.BlobMetaFile{}, err
	}
	return desc, nydus.BlobMetaFile{Name: desc.Digest.Encoded() + ".blob.meta", Data: meta}, nil
}

func isSha256Hex(name string) bool {
	if len(name) != 64 || strings.Contains(name, ".") {
		return false
	}
	_, err := digest.Parse("sha256:" + name)
	return err == nil
}
