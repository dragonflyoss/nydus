// SPDX-License-Identifier: Apache-2.0
package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Real cache layout encoding and Rust map compatibility are covered by the e2e
// suite. This helper isolates process cancellation and publication failures.
func TestCacheBuilderHelper(t *testing.T) {
	if os.Getenv("NYDUS_CACHE_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	if len(args) < 3 || args[0] != "encode" || args[1] != "--cache-dir" {
		os.Exit(20)
	}
	dir, mode := args[2], os.Getenv("NYDUS_CACHE_TEST_MODE")
	if mode == "sleep" {
		time.Sleep(time.Minute)
		os.Exit(22)
	}
	if mode != "parent" {
		if _, err := fmt.Fprint(os.Stdout, "compressed"); err != nil {
			os.Exit(23)
		}
		if mode == "fail" {
			fmt.Fprint(os.Stderr, strings.Repeat("failure", 20000))
			os.Exit(7)
		}
		id := digest.FromString("compressed").Encoded()
		if mode == "mismatch" {
			id = digest.FromString("other").Encoded()
		}
		if os.Link(filepath.Join(dir, "cache.data"), filepath.Join(dir, id+".blob.data")) != nil && mode != "retry" {
			// Retrying replaces outputs without modifying already imported inodes.
			_ = os.Remove(filepath.Join(dir, id+".blob.data"))
			if os.Link(filepath.Join(dir, "cache.data"), filepath.Join(dir, id+".blob.data")) != nil {
				os.Exit(24)
			}
		}
		for _, suffix := range []string{".blob.meta", ".group.map"} {
			if os.WriteFile(filepath.Join(dir, id+suffix), []byte("sidecar"), 0600) != nil {
				os.Exit(25)
			}
		}
		if mode == "missing-sidecar" {
			_ = os.Remove(filepath.Join(dir, id+".group.map"))
		}
	}
	if mode == "missing-bootstrap" {
		os.Exit(0)
	}
	if os.WriteFile(filepath.Join(dir, "image.boot"), []byte("bootstrap"), 0600) != nil {
		os.Exit(27)
	}
	os.Exit(0)
}

func cacheTestBuilder(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("NYDUS_CACHE_TEST_HELPER", "1")
	path := filepath.Join(dir, "builder")
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(os.Args[0], "'", "'\\''") + "' -test.run=TestCacheBuilderHelper -- \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeCacheUpload struct {
	data      bytes.Buffer
	ctx       context.Context
	block     bool
	finished  bool
	aborted   bool
	finishErr error
}

func (u *fakeCacheUpload) Write(p []byte) (int, error) {
	if u.block {
		<-u.ctx.Done()
		return 0, u.ctx.Err()
	}
	return u.data.Write(p)
}
func (u *fakeCacheUpload) Finish() (ocispec.Descriptor, error) {
	if u.finishErr != nil {
		return ocispec.Descriptor{}, u.finishErr
	}
	u.finished = true
	return ocispec.Descriptor{Digest: digest.FromBytes(u.data.Bytes()), Size: int64(u.data.Len())}, nil
}
func (u *fakeCacheUpload) Abort() {
	if !u.finished {
		u.aborted = true
	}
}

func TestEncodeCache(t *testing.T) {
	for _, mode := range []string{"success", "parent", "mismatch", "fail", "sleep", "missing-sidecar", "missing-bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("NYDUS_CACHE_TEST_MODE", mode)
			original := bytes.Repeat([]byte{42}, 4096)
			path := filepath.Join(dir, "cache.data")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(path)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if mode == "sleep" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			upload := &fakeCacheUpload{block: mode == "fail"}
			options := nydus.EncodeOption{BuilderPath: cacheTestBuilder(t, dir), CacheDir: dir}
			boot, blobs, err := encodeCache(ctx, options, func(ctx context.Context) (cacheUpload, error) {
				if mode == "parent" {
					t.Fatal("metadata-only cache layout started upload")
				}
				upload.ctx = ctx
				return upload, nil
			})
			success := mode == "success" || mode == "parent"
			if success {
				if err != nil {
					t.Fatal(err)
				}
				if boot != filepath.Join(dir, "image.boot") || len(blobs) != map[bool]int{true: 0, false: 1}[mode == "parent"] {
					t.Fatal("invalid cache layout outputs")
				}
				if mode != "parent" && !upload.finished {
					t.Fatal("upload not committed")
				}
				marker := filepath.Join(dir, "image.json")
				if _, err := os.Lstat(marker); !os.IsNotExist(err) {
					t.Fatal("encoder created a publication marker", err)
				}
				if err := os.WriteFile(marker, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := encodeCache(ctx, options, func(context.Context) (cacheUpload, error) {
					t.Fatal("published cache layout uploaded again")
					return nil, nil
				}); err == nil {
					t.Fatal("published cache layout accepted")
				}
			} else if err == nil {
				t.Fatal("expected failure")
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("source inode changed", err)
			}
			actual, _ := os.ReadFile(path)
			if !bytes.Equal(actual, original) {
				t.Fatal("source modified")
			}
		})
	}
}

func TestEncodeCacheRetriesWithoutPublicationMarker(t *testing.T) {
	for _, failure := range []string{"finish", "mismatch", "publication"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("NYDUS_CACHE_TEST_MODE", "success")
			if failure == "mismatch" {
				t.Setenv("NYDUS_CACHE_TEST_MODE", "mismatch")
			}
			if err := os.WriteFile(filepath.Join(dir, "cache.data"), []byte("payload"), 0600); err != nil {
				t.Fatal(err)
			}
			builder, first := cacheTestBuilder(t, dir), &fakeCacheUpload{}
			if failure == "finish" {
				first.finishErr = errors.New("injected Finish failure")
			}
			_, _, err := encodeCache(context.Background(), nydus.EncodeOption{BuilderPath: builder, CacheDir: dir}, func(context.Context) (cacheUpload, error) { return first, nil })
			if (failure == "publication") != (err == nil) {
				t.Fatal("unexpected first attempt", err)
			}
			t.Setenv("NYDUS_CACHE_TEST_MODE", "success")
			retry := &fakeCacheUpload{}
			_, blobs, err := encodeCache(context.Background(), nydus.EncodeOption{BuilderPath: builder, CacheDir: dir}, func(context.Context) (cacheUpload, error) { return retry, nil })
			if err != nil || !retry.finished || len(blobs) != 1 {
				t.Fatal("retry failed", err)
			}
		})
	}
}
