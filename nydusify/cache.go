// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dragonflyoss/nydus/nydusify/internal/pipeline"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type cacheCapture struct {
	Version     uint32  `json:"version"`
	DeviceIndex *uint32 `json:"device_index"`
}
type cacheResult struct {
	Digest    string              `json:"digest"`
	Size      int64               `json:"size"`
	Groups    uint32              `json:"groups"`
	DataSize  int64               `json:"data_size"`
	MetaSize  int64               `json:"meta_size"`
	MapSize   int64               `json:"map_size"`
	DataFile  string              `json:"data_file,omitempty"`
	Pruned    bool                `json:"pruned,omitempty"`
	Compacted bool                `json:"compacted,omitempty"`
	Image     *ocispec.Descriptor `json:"image,omitempty"`
}

const maxCacheJSONSize = 64 << 20

func readCacheJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCacheJSONSize {
		return fmt.Errorf("invalid or oversized cache JSON: %s", path)
	}
	reader := &io.LimitedReader{R: f, N: maxCacheJSONSize + 1}
	dec := json.NewDecoder(reader)
	if err := dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid trailing JSON in %s", path)
	}
	if reader.N == 0 {
		return fmt.Errorf("oversized cache JSON: %s", path)
	}
	return nil
}

type cacheStderr struct{ data []byte }

func (b *cacheStderr) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 8192 - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

// Reap a failed encoder even if the registry is blocking its output stream.
func runCacheBuilder(ctx context.Context, builder, capture string, output io.Writer, cancelIO context.CancelFunc, options cacheRepackOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := []string{"encode-cache", "--cache", capture}
	if options.prune {
		args = append(args, "--prune")
	}
	if options.compactMaxLayers > 0 {
		args = append(args, "--compact-max-layers", strconv.FormatUint(uint64(options.compactMaxLayers), 10))
	}
	if options.config != "" {
		args = append(args, "--config", options.config)
	}
	if options.compressor != "" {
		args = append(args, "--compressor", options.compressor)
	}
	if options.parentCacheDir != "" {
		args = append(args, "--parent-cache-dir", options.parentCacheDir)
	}
	cmd := exec.CommandContext(ctx, builder, args...)
	cmd.WaitDelay = 2 * time.Second
	stderr := &cacheStderr{}
	cmd.Stderr = stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	cmd.Stdout = writer
	if err := cmd.Start(); err != nil {
		_ = writer.Close()
		return err
	}
	_ = writer.Close()
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if err != nil {
			cancelIO()
			cancel()
			_ = reader.Close()
		}
		done <- err
	}()
	stop := context.AfterFunc(ctx, func() { _ = reader.Close() })
	defer stop()
	_, copyErr := io.Copy(output, reader)
	if copyErr != nil {
		cancelIO()
		cancel()
	}
	if waitErr := <-done; waitErr != nil {
		return fmt.Errorf("encode-cache: %w: %s", waitErr, stderr.data)
	}
	return copyErr
}

type cacheUpload interface {
	io.Writer
	Finish() (ocispec.Descriptor, error)
	Abort()
}

// A metadata-only repack must not create a registry upload session. Start it
// only when the builder emits the first bytes of a final blob.
type lazyCacheUpload struct {
	ctx    context.Context
	open   func(context.Context) (cacheUpload, error)
	upload cacheUpload
}

func (u *lazyCacheUpload) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if u.upload == nil {
		var err error
		u.upload, err = u.open(u.ctx)
		if err != nil {
			return 0, err
		}
	}
	return u.upload.Write(data)
}

func (u *lazyCacheUpload) Finish() (ocispec.Descriptor, error) {
	if u.upload == nil {
		return ocispec.Descriptor{}, fmt.Errorf("builder emitted no blob bytes")
	}
	return u.upload.Finish()
}

func (u *lazyCacheUpload) Abort() {
	if u.upload != nil {
		u.upload.Abort()
	}
}

type cacheRepackOptions struct {
	prune            bool
	compactMaxLayers uint
	config           string
	compressor       string
	parentCacheDir   string
}

func encodeCache(ctx context.Context, builder, capture string, hasParent bool, newUpload func(context.Context) (cacheUpload, error), options cacheRepackOptions) (string, []pipeline.UploadedBlob, error) {
	dir := filepath.Dir(capture)
	var input cacheCapture
	if err := readCacheJSON(capture, &input); err != nil {
		return "", nil, err
	}
	if input.Version != 1 {
		return "", nil, fmt.Errorf("unsupported capture version %d", input.Version)
	}
	if input.DeviceIndex == nil && !hasParent {
		return "", nil, fmt.Errorf("cache without new blob requires --parent-image")
	}
	resultPath := filepath.Join(dir, "cache-result.json")
	if info, err := os.Lstat(resultPath); err == nil {
		if !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("cache-result.json is not a regular file")
		}
		var previous cacheResult
		if err := readCacheJSON(resultPath, &previous); err != nil {
			return "", nil, err
		}
		if previous.Image != nil {
			return "", nil, fmt.Errorf("cache-result.json already describes a published image")
		}
		// A completed encoder does not imply a committed upload or manifest.
		// Re-encode the immutable capture after a failed publication attempt.
		if err := os.Remove(resultPath); err != nil {
			return "", nil, err
		}
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var upload cacheUpload
	output := io.Writer(rejectCacheOutput{})
	if input.DeviceIndex != nil || options.compactMaxLayers > 0 {
		upload = &lazyCacheUpload{ctx: ctx, open: newUpload}
		defer upload.Abort()
		output = upload
	}
	if err := runCacheBuilder(ctx, builder, capture, output, cancel, options); err != nil {
		return "", nil, err
	}
	var result cacheResult
	if err := readCacheJSON(filepath.Join(dir, "cache-result.json"), &result); err != nil {
		return "", nil, err
	}
	bootstrap := filepath.Join(dir, "image.boot")
	if result.Digest == "" {
		if result.Size != 0 || result.Groups != 0 || result.DataSize != 0 || result.MetaSize != 0 || result.MapSize != 0 || result.DataFile != "" || result.Compacted || input.DeviceIndex != nil {
			return "", nil, fmt.Errorf("unexpected blob in parent-only cache result")
		}
		return bootstrap, nil, nil
	}
	if upload == nil {
		return "", nil, fmt.Errorf("unexpected blob in parent-only cache result")
	}
	dataFile := "capture.data"
	if result.DataFile != "" {
		dataFile = result.DataFile
	}
	if dataFile != "capture.data" && dataFile != "compact.data" || result.Compacted != (dataFile == "compact.data") {
		return "", nil, fmt.Errorf("invalid cache data file")
	}
	dgst, err := digest.Parse(result.Digest)
	if err != nil || dgst.Algorithm() != digest.SHA256 || result.Size <= 0 || result.DataSize < 0 || result.DataSize%4096 != 0 || int64(result.Groups) > result.DataSize/4096 || result.MetaSize < 4096 || result.MetaSize%4096 != 0 || result.MapSize != 4096+(int64(result.Groups)+7)/8 {
		return "", nil, fmt.Errorf("invalid cache-result.json")
	}
	desc, err := upload.Finish()
	if err != nil {
		return "", nil, err
	}
	if desc.Digest != dgst || desc.Size != result.Size {
		return "", nil, fmt.Errorf("cache upload digest/size mismatch")
	}
	for name, size := range map[string]int64{dataFile: result.DataSize, dgst.Encoded() + ".blob.meta": result.MetaSize} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return "", nil, err
		}
		if !info.Mode().IsRegular() || info.Size() != size {
			return "", nil, fmt.Errorf("invalid capture file %s", name)
		}
	}
	if err := writeCacheMap(filepath.Join(dir, dgst.Encoded()+".group.map"), result.Groups); err != nil {
		return "", nil, err
	}
	return bootstrap, []pipeline.UploadedBlob{{Digest: dgst, Size: result.Size, MetadataPath: filepath.Join(dir, dgst.Encoded()+".blob.meta")}}, nil
}

type rejectCacheOutput struct{}

func (rejectCacheOutput) Write([]byte) (int, error) {
	return 0, fmt.Errorf("parent-only cache emitted blob bytes")
}

func writeCacheFile(path string, write func(*os.File) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".cache-output-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	defer func() { _ = file.Close() }()
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func writeCacheMap(path string, groups uint32) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if len(boot) < 8 {
		return fmt.Errorf("invalid kernel boot ID")
	}
	tag, err := strconv.ParseUint(string(boot[:8]), 16, 32)
	if err != nil {
		return err
	}
	return writeCacheFile(path, func(file *os.File) error {
		header := make([]byte, 4096)
		copy(header, "NDGRPMAP")
		binary.LittleEndian.PutUint32(header[16:], groups)
		binary.LittleEndian.PutUint32(header[20:], groups)
		binary.LittleEndian.PutUint32(header[24:], 1)
		binary.LittleEndian.PutUint32(header[28:], max(uint32(tag), 1))
		if _, err := file.Write(header); err != nil {
			return err
		}
		bitmap := make([]byte, 64<<10)
		for i := range bitmap {
			bitmap[i] = 255
		}
		remaining := (uint64(groups) + 7) / 8
		for remaining > 0 {
			n := min(remaining, uint64(len(bitmap)))
			if remaining == n && groups%8 != 0 {
				bitmap[n-1] = byte((1 << (groups % 8)) - 1)
			}
			if _, err := file.Write(bitmap[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		return nil
	})
}

func completeCachePublication(capture, bootstrap, output string, image ocispec.Descriptor) error {
	local := filepath.Join(filepath.Dir(capture), "image.boot")
	if filepath.Clean(bootstrap) != filepath.Clean(local) {
		if err := saveBootstrap(local, bootstrap); err != nil {
			return fmt.Errorf("save checkpoint bootstrap: %w", err)
		}
	}
	if output != "" && filepath.Clean(output) != filepath.Clean(local) {
		if err := saveBootstrap(output, local); err != nil {
			return fmt.Errorf("save published bootstrap: %w", err)
		}
	}
	// The published marker must follow every fallible bootstrap export so that
	// an incomplete local publication can still retry the immutable capture.
	return saveCacheImageResult(capture, image)
}

func saveCacheImageResult(capture string, image ocispec.Descriptor) error {
	path := filepath.Join(filepath.Dir(capture), "cache-result.json")
	var result cacheResult
	if err := readCacheJSON(path, &result); err != nil {
		return err
	}
	result.Image = &image
	return writeCacheFile(path, func(file *os.File) error { return json.NewEncoder(file).Encode(result) })
}

func providerCacheUpload(provider *remote.Provider, target string) func(context.Context) (cacheUpload, error) {
	return func(ctx context.Context) (cacheUpload, error) { return provider.NewBlobStreamUpload(ctx, target) }
}
