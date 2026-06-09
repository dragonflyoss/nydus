/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/converter"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// PackOption configures per-layer conversion.
type PackOption struct {
	// BuilderPath is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	BuilderPath string
	// WorkDir is a scratch directory used for layer extraction and FIFOs.
	WorkDir string
	// ChunkSize is the lepton file chunk size in bytes.
	ChunkSize uint32
	// CompressSize is the lepton group uncompressed size in bytes (a multiple of
	// 1MiB).
	CompressSize uint32
	// Compressor is the chunk data compressor ("none" or "zstd").
	Compressor string
	// LogLevel is the log level forwarded to `lepton build` (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
}

// IsLeptonBlob reports whether desc is a converted lepton data blob layer.
func IsLeptonBlob(desc ocispec.Descriptor) bool {
	return desc.MediaType == MediaTypeLeptonBlob
}

// IsLeptonBootstrap reports whether desc is a lepton bootstrap layer.
func IsLeptonBootstrap(desc ocispec.Descriptor) bool {
	if desc.Annotations == nil {
		return false
	}
	_, ok := desc.Annotations[LayerAnnotationLeptonBootstrap]
	return ok
}

// LayerConvertFunc returns a converter.ConvertFunc that converts a single OCI
// image layer into a lepton data blob layer.
//
// The OCI layer is decompressed and extracted into a scratch directory
// (preserving OCI whiteouts), then `lepton build` streams the resulting full
// blob through a FIFO directly into the content store.
func LayerConvertFunc(opt PackOption) converter.ConvertFunc {
	return func(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !images.IsLayerType(desc.MediaType) {
			return nil, nil
		}
		// Skip layers that are already in lepton format.
		if IsLeptonBlob(desc) || IsLeptonBootstrap(desc) {
			return nil, nil
		}

		newDesc, err := convertLayer(ctx, cs, desc, opt)
		if err != nil {
			return nil, errors.Wrapf(err, "convert layer %s", desc.Digest)
		}
		return newDesc, nil
	}
}

func convertLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, opt PackOption) (*ocispec.Descriptor, error) {
	// Prepare a unique scratch area for this layer.
	layerDir, err := os.MkdirTemp(opt.WorkDir, "layer-")
	if err != nil {
		return nil, errors.Wrap(err, "create scratch dir")
	}
	defer func() { _ = os.RemoveAll(layerDir) }()

	sourceDir := filepath.Join(layerDir, "rootfs")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return nil, errors.Wrap(err, "create rootfs dir")
	}

	// Decompress and extract the OCI layer into sourceDir, preserving whiteouts.
	if err := extractOCILayer(ctx, cs, desc, sourceDir); err != nil {
		return nil, err
	}

	// Stream `lepton build` output through a FIFO into the content store.
	fifoPath := filepath.Join(layerDir, "blob.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		return nil, errors.Wrap(err, "create fifo")
	}

	blobDigest, blobSize, err := buildBlobToStore(ctx, cs, desc.Digest.String(), fifoPath, BuildOption{
		BuilderPath:  opt.BuilderPath,
		SourceDir:    sourceDir,
		BlobPath:     fifoPath,
		ChunkSize:    opt.ChunkSize,
		CompressSize: opt.CompressSize,
		Compressor:   opt.Compressor,
		LogLevel:     opt.LogLevel,
	})
	if err != nil {
		return nil, err
	}

	return &ocispec.Descriptor{
		MediaType: MediaTypeLeptonBlob,
		Digest:    blobDigest,
		Size:      blobSize,
		Annotations: map[string]string{
			// A lepton full blob is self-describing and uncompressed at the
			// layer level, so the diff id equals the blob digest.
			LayerAnnotationUncompressed: blobDigest.String(),
			LayerAnnotationLeptonBlob:   "true",
		},
	}, nil
}

// extractOCILayer reads an OCI layer blob from the content store, decompresses
// it (gzip/zstd/uncompressed are auto-detected) and extracts it into dir.
func extractOCILayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, dir string) error {
	ra, err := cs.ReaderAt(ctx, desc)
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

	if err := extractTar(ctx, decompressed, dir); err != nil {
		return errors.Wrap(err, "extract layer tar")
	}
	return nil
}

// buildBlobToStore runs `lepton build`, streaming its FIFO output straight into
// the content store, and returns the committed blob digest and size.
//
// A read end of the FIFO is opened non-blocking (so it never blocks waiting for
// a writer), then switched to blocking mode. A dedicated write end is held open
// for the lifetime of the build to prevent premature EOF, and is closed only
// once the build process has exited. This makes the stream robust regardless of
// the order in which the build process opens and closes its own write end.
func buildBlobToStore(ctx context.Context, cs content.Store, srcRef, fifoPath string, opt BuildOption) (digest.Digest, int64, error) {
	rf, err := openFifoRead(fifoPath)
	if err != nil {
		return "", 0, errors.Wrap(err, "open fifo for read")
	}
	defer func() { _ = rf.Close() }()

	// Keep-alive writer: prevents the reader from observing EOF before the
	// build has finished writing.
	keepAlive, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		return "", 0, errors.Wrap(err, "open fifo keep-alive")
	}

	buildDone := make(chan error, 1)
	var closeOnce sync.Once
	go func() {
		berr := runLeptonBuild(ctx, opt)
		// Closing the keep-alive write end lets the reader drain to EOF.
		closeOnce.Do(func() { _ = keepAlive.Close() })
		buildDone <- berr
	}()

	cw, err := content.OpenWriter(ctx, cs, content.WithRef("lepton-build-"+srcRef))
	if err != nil {
		closeOnce.Do(func() { _ = keepAlive.Close() })
		<-buildDone
		return "", 0, errors.Wrap(err, "open content writer")
	}
	defer func() { _ = cw.Close() }()

	copyErr := contentCopyFrom(cw, rf)

	buildErr := <-buildDone
	if buildErr != nil {
		return "", 0, buildErr
	}
	if copyErr != nil {
		return "", 0, errors.Wrap(copyErr, "stream blob to content store")
	}

	// Record the uncompressed digest as a content-store label so that
	// containerd's images.GetDiffID takes the fast path instead of trying to
	// decompress the blob. A lepton full blob is uncompressed at the layer
	// level, so its diff id equals the blob digest.
	dgst := cw.Digest()
	if err := cw.Commit(ctx, 0, "", content.WithLabels(map[string]string{
		LayerAnnotationUncompressed: dgst.String(),
	})); err != nil && !errdefs.IsAlreadyExists(err) {
		return "", 0, errors.Wrap(err, "commit blob")
	}

	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return "", 0, errors.Wrap(err, "stat committed blob")
	}
	return dgst, info.Size, nil
}

// contentCopyFrom copies all data from r into the content writer.
func contentCopyFrom(cw content.Writer, r io.Reader) error {
	buf := make([]byte, 1<<20)
	_, err := io.CopyBuffer(cw, r, buf)
	return err
}

// openFifoRead opens the read end of a FIFO without blocking on a writer, then
// switches the descriptor to blocking mode for clean streaming reads.
func openFifoRead(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	// Switch back to blocking mode.
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
