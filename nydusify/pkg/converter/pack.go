/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
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

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// PackOption configures a single streaming layer conversion (see Pack).
type PackOption struct {
	// BuilderPath is the nydus binary path (PATH-resolvable). Defaults to "nydus".
	BuilderPath string
	// WorkDir is a scratch directory used for layer extraction and FIFOs.
	// Defaults to os.TempDir().
	WorkDir string
	// ChunkSize is the nydus file chunk size in bytes. Defaults to
	// DefaultChunkSize.
	ChunkSize uint32
	// CompressSize is the nydus group uncompressed size in bytes (a multiple of
	// 1MiB). Defaults to DefaultCompressSize.
	CompressSize uint32
	// Compressor is the chunk data compressor ("none" or "zstd"). Defaults to
	// DefaultCompressor.
	Compressor string
	// LogLevel is the log level forwarded to `nydus build` (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
}

func (opt *PackOption) applyDefaults() {
	if opt.ChunkSize == 0 {
		opt.ChunkSize = DefaultChunkSize
	}
	if opt.CompressSize == 0 {
		opt.CompressSize = DefaultCompressSize
	}
	if opt.Compressor == "" {
		opt.Compressor = DefaultCompressor
	}
}

// Pack converts an uncompressed OCI diff tar stream into a nydus full blob.
//
// The returned io.WriteCloser receives the diff tar stream. The stream is
// extracted into a scratch rootfs directory (preserving OCI whiteouts), and on
// Close `nydus build` streams the resulting full blob through a FIFO into
// dest. Close blocks until the blob is fully written to dest and returns any
// extraction or build error.
//
// Extraction requires root privileges to preserve file ownership, device nodes
// and privileged xattrs.
func Pack(ctx context.Context, dest io.Writer, opt PackOption) (io.WriteCloser, error) {
	opt.applyDefaults()

	layerDir, err := os.MkdirTemp(opt.WorkDir, "nydus-pack-")
	if err != nil {
		return nil, errors.Wrap(err, "create scratch dir")
	}

	sourceDir := filepath.Join(layerDir, "rootfs")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		_ = os.RemoveAll(layerDir)
		return nil, errors.Wrap(err, "create rootfs dir")
	}

	pr, pw := io.Pipe()
	pack := &packWriter{
		pw:         pw,
		extractErr: make(chan error, 1),
		build: func(ctx context.Context) error {
			return BuildBlob(ctx, dest, sourceDir, opt)
		},
		cleanup: func() { _ = os.RemoveAll(layerDir) },
		ctx:     ctx,
	}

	go func() {
		err := ExtractTar(ctx, pr, sourceDir)
		if err != nil {
			// Unblock the writer side on extraction failure.
			pr.CloseWithError(err)
		} else {
			_ = pr.Close()
		}
		pack.extractErr <- err
	}()

	return pack, nil
}

type packWriter struct {
	pw         *io.PipeWriter
	extractErr chan error
	build      func(context.Context) error
	cleanup    func()
	ctx        context.Context
	closed     bool
}

func (p *packWriter) Write(b []byte) (int, error) {
	return p.pw.Write(b)
}

func (p *packWriter) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	defer p.cleanup()

	if err := p.pw.Close(); err != nil {
		return errors.Wrap(err, "close extract pipe")
	}
	if err := <-p.extractErr; err != nil {
		return errors.Wrap(err, "extract layer tar")
	}
	if err := p.build(p.ctx); err != nil {
		return errors.Wrap(err, "build nydus blob")
	}
	return nil
}

// BuildBlob runs `nydus build` on sourceDir, streaming the resulting full blob
// through a FIFO into dest.
//
// A read end of the FIFO is opened non-blocking (so it never blocks waiting for
// a writer), then switched to blocking mode. A dedicated write end is held open
// for the lifetime of the build to prevent premature EOF, and is closed only
// once the build process has exited. This makes the stream robust regardless of
// the order in which the build process opens and closes its own write end.
func BuildBlob(ctx context.Context, dest io.Writer, sourceDir string, opt PackOption) error {
	opt.applyDefaults()

	fifoDir, err := os.MkdirTemp(opt.WorkDir, "nydus-fifo-")
	if err != nil {
		return errors.Wrap(err, "create fifo dir")
	}
	defer func() { _ = os.RemoveAll(fifoDir) }()

	fifoPath := filepath.Join(fifoDir, "blob.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		return errors.Wrap(err, "create fifo")
	}

	rf, err := openFifoRead(fifoPath)
	if err != nil {
		return errors.Wrap(err, "open fifo for read")
	}
	defer func() { _ = rf.Close() }()

	// Keep-alive writer: prevents the reader from observing EOF before the
	// build has finished writing.
	keepAlive, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrap(err, "open fifo keep-alive")
	}

	buildDone := make(chan error, 1)
	var closeOnce sync.Once
	go func() {
		berr := RunNydusBuild(ctx, BuildOption{
			BuilderPath:  opt.BuilderPath,
			SourceDir:    sourceDir,
			BlobPath:     fifoPath,
			ChunkSize:    opt.ChunkSize,
			CompressSize: opt.CompressSize,
			Compressor:   opt.Compressor,
			LogLevel:     opt.LogLevel,
		})
		// Closing the keep-alive write end lets the reader drain to EOF.
		closeOnce.Do(func() { _ = keepAlive.Close() })
		buildDone <- berr
	}()

	buf := make([]byte, 1<<20)
	_, copyErr := io.CopyBuffer(dest, rf, buf)

	buildErr := <-buildDone
	if buildErr != nil {
		return buildErr
	}
	if copyErr != nil {
		return errors.Wrap(copyErr, "stream blob to writer")
	}
	return nil
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
