// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package tests provides a debug test suite for investigating blobcache CI failures.
//
// This test file contains debug tests for the blobcache feature with nydusd v0.1.0.
// It helps diagnose CI failures in TestNativeLayer with specific error patterns like:
//   "fuse: reply error header OutHeader { len: 16, error: -5, unique: 34 },
//    error Custom { kind: InvalidInput, error: "Invalid argument (os error 22)" }"
//
// The test runs only when BLOBCACHE_DEBUG_TEST=true environment variable is set.
//
// Usage:
//   WORK_DIR=/tmp \
//   NYDUS_BUILDER=/path/to/latest/nydus-image \
//   NYDUS_NYDUSD=/path/to/latest/nydusd \
//   NYDUS_NYDUSD_v0_1_0=/path/to/v0.1.0/nydusd \
//   BLOBCACHE_DEBUG_TEST=true \
//   make test-blobcache-debug
//
// The test will:
// - Test the exact failing configuration (fs_version=5, lz4_block, blobcache, direct mode)
// - Run 5 iterations for each cache_compressed setting (true/false)
// - Log disk space before/after operations
// - Check and log cache directory state
// - Help identify if the issue is disk space, race condition, or configuration related
package tests

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/BraveY/snapshotter-converter/converter"
	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type BlobCacheDebugTestSuite struct {
	t *testing.T
}

// getDiskSpace returns available disk space in bytes for the given path
func getDiskSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}
	// Available space = block size * available blocks
	return stat.Bavail * uint64(stat.Bsize), nil
}

// logDiskSpace logs the available disk space for the given path
func logDiskSpace(t *testing.T, path string, prefix string) {
	space, err := getDiskSpace(path)
	if err != nil {
		t.Logf("%s: Failed to get disk space for %s: %v", prefix, path, err)
		return
	}
	spaceMB := space / (1024 * 1024)
	spaceGB := float64(space) / (1024 * 1024 * 1024)
	t.Logf("%s: Disk space for %s: %d MB (%.2f GB)", prefix, path, spaceMB, spaceGB)
}

// checkCacheFiles checks if cache files exist and logs their sizes
func checkCacheFiles(t *testing.T, cacheDir string, blobDigest digest.Digest, prefix string) {
	dataFile := filepath.Join(cacheDir, fmt.Sprintf("%s.blob.data", blobDigest.Hex()))
	metaFile := filepath.Join(cacheDir, fmt.Sprintf("%s.blob.meta", blobDigest.Hex()))

	// Check data file
	if info, err := os.Stat(dataFile); err == nil {
		t.Logf("%s: Cache data file exists: %s (size: %d bytes)", prefix, dataFile, info.Size())
	} else if os.IsNotExist(err) {
		t.Logf("%s: Cache data file does not exist: %s", prefix, dataFile)
	} else {
		t.Logf("%s: Error checking cache data file %s: %v", prefix, dataFile, err)
	}

	// Check meta file
	if info, err := os.Stat(metaFile); err == nil {
		t.Logf("%s: Cache meta file exists: %s (size: %d bytes)", prefix, metaFile, info.Size())
	} else if os.IsNotExist(err) {
		t.Logf("%s: Cache meta file does not exist: %s", prefix, metaFile)
	} else {
		t.Logf("%s: Error checking cache meta file %s: %v", prefix, metaFile, err)
	}
}

// verifyCacheDirectory walks through cache directory and logs all files
func verifyCacheDirectory(t *testing.T, cacheDir string, prefix string) {
	t.Logf("%s: Verifying cache directory: %s", prefix, cacheDir)
	err := filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Logf("%s: Error accessing %s: %v", prefix, path, err)
			return nil
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				t.Logf("%s: Error getting info for %s: %v", prefix, path, err)
				return nil
			}
			relPath, _ := filepath.Rel(cacheDir, path)
			t.Logf("%s: Cache file: %s (size: %d bytes, mode: %s)", prefix, relPath, info.Size(), info.Mode())
		}
		return nil
	})
	if err != nil {
		t.Logf("%s: Error walking cache directory: %v", prefix, err)
	}
}

// testBlobcacheV010WithConfig runs the test with specific configuration
func (b *BlobCacheDebugTestSuite) testBlobcacheV010WithConfig(t *testing.T, cacheCompressed bool, iteration int) {
	prefix := fmt.Sprintf("[Iteration %d, cache_compressed=%v]", iteration, cacheCompressed)
	t.Logf("%s Starting test", prefix)

	// Get nydusd v0.1.0 binary
	nydusdPath := tool.GetBinary(t, "NYDUS_NYDUSD", "v0.1.0")
	t.Logf("%s Using nydusd: %s", prefix, nydusdPath)

	// Create test context with specific configuration
	ctx := tool.DefaultContext(t)
	ctx.Binary.Nydusd = nydusdPath
	ctx.Build.Compressor = "lz4_block"
	ctx.Build.FSVersion = "5"
	ctx.Build.ChunkSize = "0x100000"
	ctx.Runtime.CacheType = "blobcache"
	ctx.Runtime.CacheCompressed = cacheCompressed
	ctx.Runtime.RafsMode = "direct"
	ctx.Runtime.EnablePrefetch = true
	ctx.Runtime.AmplifyIO = uint64(0x100000)

	packOption := converter.PackOption{
		BuilderPath: ctx.Binary.Builder,
		Compressor:  ctx.Build.Compressor,
		FsVersion:   ctx.Build.FSVersion,
		ChunkSize:   ctx.Build.ChunkSize,
	}

	// Prepare work directory
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	t.Logf("%s Work directory: %s", prefix, ctx.Env.WorkDir)
	t.Logf("%s Cache directory: %s", prefix, ctx.Env.CacheDir)
	t.Logf("%s Blob directory: %s", prefix, ctx.Env.BlobDir)

	// Log disk space before test
	logDiskSpace(t, ctx.Env.WorkDir, prefix+" [Before]")

	// Create test layer
	t.Logf("%s Creating test layer", prefix)
	lowerLayer := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "source-lower"))
	lowerBlobDigest := lowerLayer.Pack(t, packOption, ctx.Env.BlobDir)
	t.Logf("%s Created blob with digest: %s", prefix, lowerBlobDigest)

	mergeOption := converter.MergeOption{
		BuilderPath: ctx.Binary.Builder,
	}
	actualDigests, lowerBootstrap := tool.MergeLayers(t, *ctx, mergeOption, []converter.Layer{
		{
			Digest: lowerBlobDigest,
		},
	})
	require.Equal(t, []digest.Digest{lowerBlobDigest}, actualDigests)
	t.Logf("%s Bootstrap created: %s", prefix, lowerBootstrap)

	// Check cache directory before mounting
	t.Logf("%s Cache directory state before mounting:", prefix)
	verifyCacheDirectory(t, ctx.Env.CacheDir, prefix+" [Pre-mount]")

	// Verify layer with nydusd
	ctx.Env.BootstrapPath = lowerBootstrap
	t.Logf("%s Mounting and verifying layer", prefix)

	// Log disk space before mount
	logDiskSpace(t, ctx.Env.WorkDir, prefix+" [Before mount]")

	// Verify the layer (this will mount nydusd and access files)
	tool.Verify(t, *ctx, lowerLayer.FileTree)

	t.Logf("%s Verification successful", prefix)

	// Log disk space after verification
	logDiskSpace(t, ctx.Env.WorkDir, prefix+" [After verification]")

	// Check cache files after mounting
	t.Logf("%s Cache directory state after verification:", prefix)
	checkCacheFiles(t, ctx.Env.CacheDir, lowerBlobDigest, prefix+" [Post-mount]")
	verifyCacheDirectory(t, ctx.Env.CacheDir, prefix+" [Post-mount]")

	t.Logf("%s Test completed successfully", prefix)
}

// TestBlobcacheV010Debug tests the failing blobcache configuration with nydusd v0.1.0
func (b *BlobCacheDebugTestSuite) TestBlobcacheV010Debug() test.Generator {
	return func() (name string, testCase test.Case) {
		// Only run this test if BLOBCACHE_DEBUG_TEST environment variable is set
		if os.Getenv("BLOBCACHE_DEBUG_TEST") != "true" {
			return "", nil
		}

		return "blobcache_v0.1.0_debug", func(t *testing.T) {
			t.Log("Starting BlobcacheV010Debug test suite")
			t.Log("This test helps debug CI failures with TestNativeLayer using nydusd v0.1.0")

			// Test both cache_compressed configurations multiple times
			iterations := 5

			for i := 1; i <= iterations; i++ {
				t.Run(fmt.Sprintf("cache_compressed=true/iteration=%d", i), func(t *testing.T) {
					b.testBlobcacheV010WithConfig(t, true, i)
				})
			}

			for i := 1; i <= iterations; i++ {
				t.Run(fmt.Sprintf("cache_compressed=false/iteration=%d", i), func(t *testing.T) {
					b.testBlobcacheV010WithConfig(t, false, i)
				})
			}

			t.Log("All debug test iterations completed")
		}
	}
}

func TestBlobcacheV010Debug(t *testing.T) {
	test.Run(t, &BlobCacheDebugTestSuite{t: t})
}
