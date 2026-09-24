/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

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
	// WorkDir holds temporary FIFOs and sidecars; defaults to os.TempDir().
	WorkDir string
	// ChunkSize is the file chunk size; zero selects DefaultChunkSize.
	ChunkSize uint32
	// Compressor selects a supported data layout/algorithm; defaults to DefaultCompressor.
	Compressor string
	// LogLevel is the log level forwarded to `nydus build` (trace/debug/info/
	// warn/error). Defaults to "info" when empty.
	LogLevel string
}

func (opt *PackOption) applyDefaults() {
	if opt.Compressor == "" {
		opt.Compressor = DefaultCompressor
	}
	if opt.ChunkSize == 0 {
		opt.ChunkSize = DefaultChunkSize
	}
}

// Pack streams an OCI diff tar, normalized to the tree containerd applies from
// it (see normalizeTar), into nydus build without extracting a rootfs.
// Close waits for the build and output copy; neither requires root privileges.
func Pack(ctx context.Context, dest io.Writer, opt PackOption) (io.WriteCloser, error) {
	opt.applyDefaults()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	pack := &packWriter{
		pw:     pw,
		done:   make(chan error, 1),
		cancel: cancel,
	}
	stop := context.AfterFunc(ctx, func() {
		_ = pr.CloseWithError(ctx.Err())
		_ = pw.CloseWithError(ctx.Err())
	})
	go func() {
		err := buildBlob(ctx, dest, "/dev/stdin", pr, opt)
		stop()
		_ = pr.CloseWithError(err)
		pack.done <- err
	}()
	return pack, nil
}

// pipeIO joins the layer input and builder stdin, remembering the first I/O
// failure on either so it is not mistaken for a rejected layer.
type pipeIO struct {
	r   io.Reader
	w   io.Writer
	err error
}

func (p *pipeIO) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err != nil && err != io.EOF && p.err == nil {
		p.err = err
	}
	return n, err
}

func (p *pipeIO) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if err != nil && p.err == nil {
		p.err = err
	}
	return n, err
}

type packWriter struct {
	pw        *io.PipeWriter
	done      chan error
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (p *packWriter) Write(b []byte) (int, error) {
	return p.pw.Write(b)
}

func (p *packWriter) Close() error {
	p.closeOnce.Do(func() {
		defer p.cancel()
		_ = p.pw.Close()
		p.closeErr = <-p.done
	})
	return p.closeErr
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
	return buildBlob(ctx, dest, sourceDir, nil, opt)
}

func buildBlob(ctx context.Context, dest io.Writer, sourcePath string, input *io.PipeReader, opt PackOption) error {
	opt.applyDefaults()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if input != nil {
		stop := context.AfterFunc(ctx, func() { _ = input.CloseWithError(ctx.Err()) })
		defer stop()
	}

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
	go func() {
		sourceType := "dir"
		var stdin io.Reader
		var inputDone chan error
		var sourceFile *os.File
		if input != nil {
			sourceType = "tar"
			reader, writer, err := os.Pipe()
			if err != nil {
				_ = keepAlive.Close()
				buildDone <- err
				return
			}
			sourceFile = reader
			stdin = reader
			inputDone = make(chan error, 1)
			go func() {
				pipe := &pipeIO{r: input, w: writer}
				err := normalizeTar(pipe, pipe)
				if err != nil {
					_ = input.CloseWithError(err)
				}
				_ = writer.Close()
				if pipe.err != nil {
					// A pipe closed by the builder or the caller; their own
					// error explains why.
					err = nil
				}
				inputDone <- err
			}()
		}
		berr := RunNydusBuild(ctx, BuildOption{
			BuilderPath: opt.BuilderPath,
			SourceDir:   sourcePath,
			SourceType:  sourceType,
			Stdin:       stdin,
			BlobPath:    fifoPath,
			ChunkSize:   opt.ChunkSize,
			Compressor:  opt.Compressor,
			LogLevel:    opt.LogLevel,
		})
		if input != nil {
			_ = sourceFile.Close()
			_ = input.CloseWithError(berr)
			if inputErr := <-inputDone; inputErr != nil {
				// A rejected layer tar overrides whatever the builder made of
				// the truncated stream.
				berr = inputErr
			}
		}
		// Closing the keep-alive write end lets the reader drain to EOF.
		_ = keepAlive.Close()
		buildDone <- berr
	}()

	buf := make([]byte, 1<<20)
	_, copyErr := io.CopyBuffer(dest, rf, buf)
	if copyErr != nil {
		cancel()
		_ = rf.Close()
	}

	buildErr := <-buildDone
	if copyErr != nil {
		return errors.Wrap(copyErr, "stream blob to writer")
	}
	return buildErr
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
