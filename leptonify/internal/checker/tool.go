/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/lepton/leptonify/internal/converter"
)

func builderBinary(path string) string {
	if path == "" {
		return "lepton"
	}
	return path
}

// extractBootstrap reads a lepton bootstrap layer (gzip(tar(image/image.boot)))
// from the content store and writes the embedded bootstrap file to destPath.
func extractBootstrap(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destPath string) error {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "open bootstrap reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return errors.Wrap(err, "decompress bootstrap layer")
	}
	defer func() { _ = decompressed.Close() }()

	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read bootstrap tar")
		}
		if hdr.Name != converter.BootstrapFileNameInLayer {
			continue
		}
		out, err := os.Create(destPath)
		if err != nil {
			return errors.Wrap(err, "create bootstrap file")
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return errors.Wrap(err, "write bootstrap file")
		}
		if err := out.Close(); err != nil {
			return errors.Wrap(err, "close bootstrap file")
		}
		return nil
	}
	return errors.Errorf("bootstrap entry %q not found in layer", converter.BootstrapFileNameInLayer)
}

// materializeBlobs writes each lepton data blob from the content store into
// blobDir. The lepton check / fuse subcommands resolve blobs by content hash, so
// the file name is irrelevant; the descriptor digest is used for convenience.
func materializeBlobs(ctx context.Context, cs content.Store, blobs []ocispec.Descriptor, blobDir string) error {
	for _, blob := range blobs {
		if err := materializeBlob(ctx, cs, blob, filepath.Join(blobDir, blob.Digest.Encoded())); err != nil {
			return errors.Wrapf(err, "materialize blob %s", blob.Digest)
		}
	}
	return nil
}

func materializeBlob(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destPath string) error {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "open blob reader")
	}
	defer func() { _ = ra.Close() }()

	out, err := os.Create(destPath)
	if err != nil {
		return errors.Wrap(err, "create blob file")
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, io.NewSectionReader(ra, 0, ra.Size())); err != nil {
		return errors.Wrap(err, "copy blob")
	}
	return out.Close()
}

// applyOCIImage applies all OCI layers of img sequentially into rootfs,
// resolving whiteouts so the result is the fully merged root filesystem.
func applyOCIImage(ctx context.Context, cs content.Store, img *Image, rootfs string) error {
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return errors.Wrap(err, "create rootfs dir")
	}
	for _, layer := range img.Manifest.Layers {
		if err := applyOCILayer(ctx, cs, layer, rootfs); err != nil {
			return errors.Wrapf(err, "apply layer %s", layer.Digest)
		}
	}
	return nil
}

func applyOCILayer(ctx context.Context, cs content.Store, layer ocispec.Descriptor, rootfs string) error {
	ra, err := cs.ReaderAt(ctx, layer)
	if err != nil {
		return errors.Wrap(err, "open layer reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return errors.Wrap(err, "decompress layer")
	}
	defer func() { _ = decompressed.Close() }()

	// Preserve the original uid/gid recorded in the layer so the comparison
	// reflects the real image ownership (requires root, enforced by the
	// filesystem rule's privilege precheck).
	if _, err := archive.Apply(ctx, rootfs, decompressed); err != nil {
		return errors.Wrap(err, "apply layer archive")
	}
	return nil
}

// runLeptonCheck invokes `lepton check` to statically validate a bootstrap and
// its referenced blobs.
func runLeptonCheck(ctx context.Context, builder, bootstrapPath, blobDir string) error {
	args := []string{
		"check",
		"--bootstrap", bootstrapPath,
		"--blob-dir", blobDir,
	}
	cmd := exec.CommandContext(ctx, builderBinary(builder), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "lepton check failed: %s", stderr.String())
	}
	return nil
}
