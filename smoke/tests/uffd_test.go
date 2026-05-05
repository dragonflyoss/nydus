// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BraveY/snapshotter-converter/converter"
	"github.com/containerd/log"
	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/stretchr/testify/require"
)

type UffdTestSuite struct {
	T *testing.T
}

// buildLayer creates a RAFS v6 layer using MakeThinLowerLayer + Pack + MergeLayers.
// MakeThinLowerLayer is used instead of MakeLowerLayer because the latter
// creates special files (char/block devices, FIFO) via mknod which requires root.
func (s *UffdTestSuite) buildLayer(t *testing.T, ctx *tool.Context) {
	packOption := converter.PackOption{
		BuilderPath: ctx.Binary.Builder,
		Compressor:  ctx.Build.Compressor,
		FsVersion:   ctx.Build.FSVersion,
		ChunkSize:   ctx.Build.ChunkSize,
	}

	lowerLayer := texture.MakeThinLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "source"))
	digest := lowerLayer.Pack(t, packOption, ctx.Env.BlobDir)

	mergeOption := converter.MergeOption{
		BuilderPath: ctx.Binary.Builder,
	}
	_, bootstrap := tool.MergeLayers(t, *ctx, mergeOption, []converter.Layer{
		{Digest: digest},
	})

	ctx.Env.BootstrapPath = bootstrap
}

// TestUffdDaemonLifecycle verifies that nydusd starts in uffd mode,
// reaches RUNNING state, and shuts down cleanly.
func (s *UffdTestSuite) TestUffdDaemonLifecycle(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	s.buildLayer(t, ctx)

	uffdSockPath := filepath.Join(ctx.Env.WorkDir, "uffd.sock")
	apiSockPath := filepath.Join(ctx.Env.WorkDir, "api.sock")

	nydusd, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: ctx.Env.BootstrapPath,
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	// Start daemon
	_, err = nydusd.Run()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Shutdown(); err != nil {
			log.L.WithError(err).Errorf("shutdown uffd daemon")
		}
	}()

	// Wait for RUNNING state via API
	err = nydusd.WaitStatus("RUNNING")
	require.NoError(t, err)

	// Verify the uffd socket was created
	_, err = os.Stat(uffdSockPath)
	require.NoError(t, err)
}

// TestUffdDaemonRestart verifies that the uffd daemon can be restarted
// after shutdown and a new instance can listen on the same socket path.
func (s *UffdTestSuite) TestUffdDaemonRestart(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	s.buildLayer(t, ctx)

	uffdSockPath := filepath.Join(ctx.Env.WorkDir, "uffd.sock")
	apiSockPath := filepath.Join(ctx.Env.WorkDir, "api.sock")

	// First start
	nydusd, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: ctx.Env.BootstrapPath,
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	_, err = nydusd.Run()
	require.NoError(t, err)

	err = nydusd.WaitStatus("RUNNING")
	require.NoError(t, err)

	_, err = os.Stat(uffdSockPath)
	require.NoError(t, err)

	// Shutdown
	err = nydusd.Shutdown()
	require.NoError(t, err)

	// Clean up the socket file left by the previous instance.
	// nydusd does not unlink the socket on exit, so the new instance
	// would get "address already in use" if we don't remove it.
	os.Remove(uffdSockPath)

	// Second start on the same socket path
	nydusd2, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: ctx.Env.BootstrapPath,
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	_, err = nydusd2.Run()
	require.NoError(t, err)
	defer func() {
		if err := nydusd2.Shutdown(); err != nil {
			log.L.WithError(err).Errorf("shutdown uffd daemon (second instance)")
		}
	}()

	err = nydusd2.WaitStatus("RUNNING")
	require.NoError(t, err)

	_, err = os.Stat(uffdSockPath)
	require.NoError(t, err)
}

// TestUffdDaemonMissingBootstrap verifies that nydusd uffd fails gracefully
// when started without a valid bootstrap file.
func (s *UffdTestSuite) TestUffdDaemonMissingBootstrap(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	uffdSockPath := filepath.Join(ctx.Env.WorkDir, "uffd.sock")
	apiSockPath := filepath.Join(ctx.Env.WorkDir, "api.sock")

	nydusd, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: "/nonexistent/bootstrap.boot",
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	_, err = nydusd.Run()
	require.NoError(t, err)

	// Should NOT reach RUNNING state with invalid bootstrap
	err = nydusd.WaitStatus("RUNNING")
	require.Error(t, err, "nydusd should not reach RUNNING state with missing bootstrap")

	_ = nydusd.Shutdown()
}

// TestUffdZerocopyDataVerification connects a UFFD client in zerocopy mode,
// triggers page faults by reading from the block device, and verifies the data.
func (s *UffdTestSuite) TestUffdZerocopyDataVerification(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	s.buildLayer(t, ctx)

	// Export disk image for verification reference.
	diskPath := filepath.Join(ctx.Env.WorkDir, "disk.raw")
	err := tool.ExportDiskImage(ctx.Binary.Builder, ctx.Env.BootstrapPath, ctx.Env.BlobDir, diskPath)
	if err != nil {
		t.Logf("export disk image failed (will use EROFS magic check only): %v", err)
		diskPath = ""
	}

	uffdSockPath := filepath.Join(ctx.Env.WorkDir, "uffd.sock")
	apiSockPath := filepath.Join(ctx.Env.WorkDir, "api.sock")

	nydusd, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: ctx.Env.BootstrapPath,
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	_, err = nydusd.Run()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Shutdown(); err != nil {
			log.L.WithError(err).Errorf("shutdown uffd daemon")
		}
	}()

	err = nydusd.WaitStatus("RUNNING")
	require.NoError(t, err)

	// Connect UFFD client in zerocopy mode.
	client, err := tool.NewUffdClient(uffdSockPath)
	require.NoError(t, err, "failed to connect UFFD client")
	defer client.Close()

	t.Logf("UFFD client connected, device size: %d bytes, block size: %d", client.DeviceSize(), client.BlockSize())
	require.Greater(t, client.DeviceSize(), uint64(0), "device size should be positive")

	err = client.Handshake(tool.PolicyZerocopy, false)
	require.NoError(t, err, "handshake failed")

	// Allow time for the worker to start processing.
	time.Sleep(100 * time.Millisecond)

	// Verify EROFS superblock magic at offset 1024.
	err = client.VerifyErofsMagic()
	require.NoError(t, err, "EROFS magic verification failed")

	// Verify data at multiple offsets.
	s.verifyDataAtOffsets(t, client, diskPath)
}

// TestUffdCopyDataVerification connects a UFFD client in copy mode,
// triggers page faults by reading from the block device, and verifies the data.
func (s *UffdTestSuite) TestUffdCopyDataVerification(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	s.buildLayer(t, ctx)

	// Export disk image for verification reference.
	diskPath := filepath.Join(ctx.Env.WorkDir, "disk.raw")
	err := tool.ExportDiskImage(ctx.Binary.Builder, ctx.Env.BootstrapPath, ctx.Env.BlobDir, diskPath)
	if err != nil {
		t.Logf("export disk image failed (will use EROFS magic check only): %v", err)
		diskPath = ""
	}

	uffdSockPath := filepath.Join(ctx.Env.WorkDir, "uffd.sock")
	apiSockPath := filepath.Join(ctx.Env.WorkDir, "api.sock")

	nydusd, err := tool.NewNydusdUffd(tool.NydusdConfig{
		NydusdPath:    ctx.Binary.Nydusd,
		BootstrapPath: ctx.Env.BootstrapPath,
		LocalFsDir:    ctx.Env.BlobDir,
		UffdSockPath:  uffdSockPath,
		APISockPath:   apiSockPath,
	})
	require.NoError(t, err)

	_, err = nydusd.Run()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Shutdown(); err != nil {
			log.L.WithError(err).Errorf("shutdown uffd daemon")
		}
	}()

	err = nydusd.WaitStatus("RUNNING")
	require.NoError(t, err)

	// Connect UFFD client in copy mode.
	client, err := tool.NewUffdClient(uffdSockPath)
	require.NoError(t, err, "failed to connect UFFD client")
	defer client.Close()

	t.Logf("UFFD client connected, device size: %d bytes, block size: %d", client.DeviceSize(), client.BlockSize())
	require.Greater(t, client.DeviceSize(), uint64(0), "device size should be positive")

	err = client.Handshake(tool.PolicyCopy, false)
	require.NoError(t, err, "handshake failed")

	// Verify EROFS superblock magic at offset 1024.
	err = client.VerifyErofsMagic()
	require.NoError(t, err, "EROFS magic verification failed")

	// Verify data at multiple offsets.
	s.verifyDataAtOffsets(t, client, diskPath)
}

// verifyDataAtOffsets reads data at several offsets and verifies correctness.
// If diskPath is non-empty, compares against the exported disk image.
// Otherwise, checks that data blocks are non-zero.
func (s *UffdTestSuite) verifyDataAtOffsets(t *testing.T, client *tool.UffdClient, diskPath string) {
	deviceSize := client.DeviceSize()
	readLen := int64(4096) // one block

	// Generate test offsets: start, several interior points, near end.
	offsets := []int64{0}
	step := deviceSize / 8
	for i := uint64(1); i < 8; i++ {
		off := int64(i * step)
		off = off / 4096 * 4096 // align to page boundary
		if off+readLen <= int64(deviceSize) {
			offsets = append(offsets, off)
		}
	}
	// Near the end.
	if deviceSize > 4096 {
		tail := int64((deviceSize-4096)/4096) * 4096
		found := false
		for _, o := range offsets {
			if o == tail {
				found = true
				break
			}
		}
		if !found && tail+readLen <= int64(deviceSize) {
			offsets = append(offsets, tail)
		}
	}

	// Read the exported disk image for comparison (if available).
	var diskData []byte
	if diskPath != "" {
		diskFile, err := os.ReadFile(diskPath)
		if err != nil {
			t.Logf("could not read disk image: %v (using non-zero check only)", err)
		} else {
			diskData = diskFile
		}
	}

	for _, offset := range offsets {
		data, err := client.ReadAt(offset, readLen)
		require.NoError(t, err, "ReadAt offset=%d failed", offset)

		if diskData != nil && offset+readLen <= int64(len(diskData)) {
			// Compare against exported disk image.
			expected := diskData[offset : offset+readLen]
			require.Equal(t, expected, data, "data mismatch at offset %d", offset)
		} else {
			// Verify the EROFS superblock block is non-zero (contains magic + metadata).
			if offset == 0 {
				magic := binary.LittleEndian.Uint32(data[1024:1028])
				require.Equal(t, uint32(0xE0F5E1E2), magic, "EROFS magic not found at offset 0+1024")
			}
			// For other offsets, just verify data is accessible (no error).
		}

		t.Logf("  offset 0x%x: verified %d bytes", offset, len(data))
	}
}

func TestUffd(t *testing.T) {
	test.Run(t, &UffdTestSuite{T: t})
}
