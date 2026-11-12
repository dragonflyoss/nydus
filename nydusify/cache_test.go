package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestCacheBuilderHelper(t *testing.T) {
	if os.Getenv("NYDUS_CACHE_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	if len(args) != 3 || args[0] != "encode-cache" || args[1] != "--cache" {
		os.Exit(20)
	}
	dir := filepath.Dir(args[2])
	mode := os.Getenv("NYDUS_CACHE_TEST_MODE")
	if mode == "sleep" {
		time.Sleep(time.Minute)
		os.Exit(21)
	}
	var input cacheCapture
	if readCacheJSON(args[2], &input) != nil {
		os.Exit(22)
	}
	result := cacheResult{}
	if input.DeviceIndex != nil {
		data, err := os.ReadFile(filepath.Join(dir, "capture.data"))
		if err != nil {
			os.Exit(23)
		}
		if _, err := fmt.Fprint(os.Stdout, "compressed"); err != nil {
			os.Exit(31)
		}
		if mode == "fail" {
			fmt.Fprint(os.Stderr, strings.Repeat("failure", 20000))
			os.Exit(7)
		}
		groups := uint32(1)
		if len(data) == 0 {
			groups = 0
		}
		result = cacheResult{Digest: digest.FromString("compressed").String(), Size: 10, Groups: groups, DataSize: int64(len(data)), MetaSize: 4096, MapSize: 4096 + (int64(groups)+7)/8}
		if mode == "mismatch" {
			result.Size++
		}
		meta := make([]byte, 4096)
		copy(meta, "NDBLMETA")
		binary.LittleEndian.PutUint32(meta[16:], crc32.Checksum(meta, crc32.MakeTable(crc32.Castagnoli)))
		if os.WriteFile(filepath.Join(dir, digest.FromString("compressed").Encoded()+".blob.meta"), meta, 0600) != nil {
			os.Exit(24)
		}
	}
	b, _ := json.Marshal(result)
	if os.WriteFile(filepath.Join(dir, "cache-result.json"), b, 0600) != nil {
		os.Exit(25)
	}
	if os.WriteFile(filepath.Join(dir, "image.boot"), []byte("bootstrap"), 0600) != nil {
		os.Exit(26)
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

func TestEncodeCacheUsesFilesOnly(t *testing.T) {
	for _, mode := range []string{"success", "empty-full", "parent", "mismatch", "fail", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("NYDUS_CACHE_TEST_MODE", mode)
			capture := filepath.Join(dir, "capture.json")
			plan := `{"version":1,"device_index":0}`
			if mode == "parent" {
				plan = `{"version":1,"device_index":null}`
			}
			if err := os.WriteFile(capture, []byte(plan), 0600); err != nil {
				t.Fatal(err)
			}
			data := bytes.Repeat([]byte{42}, 4096)
			if mode == "empty-full" || mode == "parent" {
				data = nil
			}
			dataPath := filepath.Join(dir, "capture.data")
			if err := os.WriteFile(dataPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(dataPath)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if mode == "sleep" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
			}
			upload := &fakeCacheUpload{block: mode == "fail"}
			boot, blobs, err := encodeCache(ctx, cacheTestBuilder(t, dir), capture, mode == "parent", func(ctx context.Context) (cacheUpload, error) {
				upload.ctx = ctx
				if mode == "parent" {
					t.Fatal("parent-only upload")
				}
				return upload, nil
			})
			if mode == "success" || mode == "empty-full" || mode == "parent" {
				if err != nil {
					t.Fatal(err)
				}
				if boot != filepath.Join(dir, "image.boot") {
					t.Fatal(boot)
				}
				if mode != "parent" {
					if len(blobs) != 1 || !upload.finished {
						t.Fatal("upload not finalized")
					}
					mapPath := filepath.Join(dir, blobs[0].Digest.Encoded()+".group.map")
					bitmap, err := os.ReadFile(mapPath)
					if err != nil {
						t.Fatal(err)
					}
					groups := uint32(1)
					if mode == "empty-full" {
						groups = 0
					}
					if binary.LittleEndian.Uint32(bitmap[16:]) != groups || binary.LittleEndian.Uint32(bitmap[24:]) != 1 || binary.LittleEndian.Uint32(bitmap[28:]) == 0 {
						t.Fatal("invalid ready map")
					}
					if groups > 0 && bitmap[4096] != 1 {
						t.Fatal("invalid ready bit")
					}
				} else if len(blobs) != 0 {
					t.Fatal("parent-only blob")
				}
				image := ocispec.Descriptor{Digest: digest.FromString("manifest"), Size: 8, MediaType: ocispec.MediaTypeImageManifest}
				if err := saveCacheImageResult(capture, image); err != nil {
					t.Fatal(err)
				}
				var result cacheResult
				if err := readCacheJSON(filepath.Join(dir, "cache-result.json"), &result); err != nil || result.Image == nil || result.Image.Digest != image.Digest {
					t.Fatal("missing OCI result", err)
				}
			} else if err == nil {
				t.Fatal("expected failure")
			}
			after, err := os.Stat(dataPath)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("source data inode changed", err)
			}
			actual, _ := os.ReadFile(dataPath)
			if !bytes.Equal(actual, data) {
				t.Fatal("source data modified")
			}
			if mode == "success" || mode == "parent" || mode == "empty-full" {
				if _, _, err := encodeCache(ctx, cacheTestBuilder(t, dir), capture, true, func(context.Context) (cacheUpload, error) { t.Fatal("stale result accepted"); return nil, nil }); err == nil {
					t.Fatal("stale result accepted")
				}
			}
		})
	}
}

func TestEncodeCacheRetriesUnpublishedResults(t *testing.T) {
	for _, failure := range []string{"finish", "mismatch", "publication", "bootstrap"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("NYDUS_CACHE_TEST_MODE", "success")
			if failure == "mismatch" {
				t.Setenv("NYDUS_CACHE_TEST_MODE", "mismatch")
			}
			capture := filepath.Join(dir, "capture.json")
			if err := os.WriteFile(capture, []byte(`{"version":1,"device_index":0}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "capture.data"), bytes.Repeat([]byte{42}, 4096), 0600); err != nil {
				t.Fatal(err)
			}
			builder := cacheTestBuilder(t, dir)
			first := &fakeCacheUpload{}
			if failure == "finish" {
				first.finishErr = fmt.Errorf("injected Finish failure")
			}
			_, _, err := encodeCache(context.Background(), builder, capture, false, func(context.Context) (cacheUpload, error) { return first, nil })
			if failure == "publication" || failure == "bootstrap" {
				if err != nil {
					t.Fatal(err)
				}
				// Simulate a manifest push failure after upload completion.
				if failure == "bootstrap" {
					image := ocispec.Descriptor{Digest: digest.FromString("published"), Size: 8, MediaType: ocispec.MediaTypeImageManifest}
					if err := completeCachePublication(capture, filepath.Join(dir, "image.boot"), filepath.Join(dir, "missing", "image.boot"), image); err == nil {
						t.Fatal("expected bootstrap export failure")
					}
				}
			} else if err == nil {
				t.Fatal("expected injected failure")
			}
			t.Setenv("NYDUS_CACHE_TEST_MODE", "success")
			retry := &fakeCacheUpload{}
			_, blobs, err := encodeCache(context.Background(), builder, capture, false, func(context.Context) (cacheUpload, error) { return retry, nil })
			if err != nil || !retry.finished || len(blobs) != 1 {
				t.Fatalf("retry failed: %v", err)
			}
			image := ocispec.Descriptor{Digest: digest.FromString("published"), Size: 8, MediaType: ocispec.MediaTypeImageManifest}
			if err := saveCacheImageResult(capture, image); err != nil {
				t.Fatal(err)
			}
			if _, _, err := encodeCache(context.Background(), builder, capture, false, func(context.Context) (cacheUpload, error) {
				t.Fatal("published capture uploaded again")
				return nil, nil
			}); err == nil {
				t.Fatal("published capture accepted")
			}
		})
	}
}

func TestWriteCacheFilePreservesOutputOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := mockFile(t, filepath.Join(dir, "cache-result.json"), "original")
	failure := errors.New("write failed")
	err := writeCacheFile(path, func(file *os.File) error {
		if _, err := file.WriteString("partial"); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("write error was replaced: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("published output changed: %q, %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("temporary output was not removed: %v, %v", entries, err)
	}
}

func TestCompleteCachePublication(t *testing.T) {
	for _, mode := range []string{"unchanged", "pruned", "explicit output", "checkpoint failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			capture := filepath.Join(dir, "capture.json")
			local := filepath.Join(dir, "image.boot")
			mockFile(t, local, "original")
			mockFile(t, filepath.Join(dir, "cache-result.json"), "{}")
			bootstrap, output, expected := local, "", "original"
			if mode != "unchanged" {
				bootstrap = mockFile(t, filepath.Join(dir, "repacked.boot"), "pruned")
				expected = "pruned"
			}
			if mode == "explicit output" {
				output = filepath.Join(dir, "export.boot")
			}
			if mode == "checkpoint failure" {
				if err := os.Remove(local); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(local, 0700); err != nil {
					t.Fatal(err)
				}
			}
			image := ocispec.Descriptor{Digest: digest.FromString("published"), Size: 8, MediaType: ocispec.MediaTypeImageManifest}
			err := completeCachePublication(capture, bootstrap, output, image)
			var result cacheResult
			if readErr := readCacheJSON(filepath.Join(dir, "cache-result.json"), &result); readErr != nil {
				t.Fatal(readErr)
			}
			if mode == "checkpoint failure" {
				if err == nil || result.Image != nil {
					t.Fatalf("failed checkpoint export marked published: %v, %+v", err, result)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Image == nil || result.Image.Digest != image.Digest {
				t.Fatalf("missing publication result: %+v", result)
			}
			for _, path := range []string{local, output} {
				if path == "" {
					continue
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != expected {
					t.Fatalf("bootstrap %s: %q, %v", path, data, err)
				}
			}
		})
	}
}
