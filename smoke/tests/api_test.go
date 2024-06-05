// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/smoke/tests/texture"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
)

type APIV1TestSuite struct{}

// func (a *APIV1TestSuite) TestDaemonStatus(t *testing.T) {

// 	ctx := tool.DefaultContext(t)

// 	ctx.PrepareWorkDir(t)
// 	defer ctx.Destroy(t)

// 	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

// 	rafs := a.rootFsToRafs(t, ctx, rootFs)

// 	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
// 		NydusdPath:      ctx.Binary.Nydusd,
// 		BootstrapPath:   rafs,
// 		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
// 		MountPath:       ctx.Env.MountDir,
// 		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
// 		BackendType:     "localfs",
// 		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
// 		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
// 		BlobCacheDir:    ctx.Env.CacheDir,
// 		CacheType:       ctx.Runtime.CacheType,
// 		CacheCompressed: ctx.Runtime.CacheCompressed,
// 		RafsMode:        ctx.Runtime.RafsMode,
// 		DigestValidate:  false,
// 	})
// 	require.NoError(t, err)

// 	err = nydusd.Mount()
// 	require.NoError(t, err)
// 	defer func() {
// 		if err := nydusd.Umount(); err != nil {
// 			log.L.WithError(err).Errorf("umount")
// 		}
// 	}()

// 	// The implementation of runNydusd() has checked stats, however,
// 	// it's clear of semantic to check stats again.
// 	newCtx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	select {
// 	case <-tool.CheckReady(newCtx, nydusd.APISockPath):
// 		return
// 	case <-time.After(50 * time.Millisecond):
// 		require.Fail(t, "nydusd status is not RUNNING")
// 	}
// }

// func (a *APIV1TestSuite) TestMetrics(t *testing.T) {

// 	ctx := tool.DefaultContext(t)

// 	ctx.PrepareWorkDir(t)
// 	defer ctx.Destroy(t)

// 	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

// 	rafs := a.rootFsToRafs(t, ctx, rootFs)

// 	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
// 		NydusdPath:      ctx.Binary.Nydusd,
// 		BootstrapPath:   rafs,
// 		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
// 		MountPath:       ctx.Env.MountDir,
// 		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
// 		BackendType:     "localfs",
// 		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
// 		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
// 		BlobCacheDir:    ctx.Env.CacheDir,
// 		CacheType:       ctx.Runtime.CacheType,
// 		CacheCompressed: ctx.Runtime.CacheCompressed,
// 		RafsMode:        ctx.Runtime.RafsMode,
// 		DigestValidate:  false,
// 		IOStatsFiles:    true,
// 		LatestReadFiles: true,
// 		AccessPattern:   true,
// 	})
// 	require.NoError(t, err)

// 	err = nydusd.Mount()
// 	require.NoError(t, err)
// 	defer func() {
// 		if err := nydusd.Umount(); err != nil {
// 			log.L.WithError(err).Errorf("umount")
// 		}
// 	}()

// 	err = a.visit(filepath.Join(ctx.Env.MountDir, "file-1"))
// 	require.NoError(t, err)

// 	gm, err := nydusd.GetGlobalMetrics()
// 	require.NoError(t, err)
// 	require.True(t, gm.FilesAccountEnabled)
// 	require.True(t, gm.MeasureLatency)
// 	require.True(t, gm.AccessPattern)
// 	require.Equal(t, uint64(len("file-1")), gm.DataRead)
// 	require.Equal(t, uint64(1), gm.FOPS[4])

// 	err = a.visit(filepath.Join(ctx.Env.MountDir, "dir-1/file-1"))
// 	require.NoError(t, err)
// 	gmNew, err := nydusd.GetGlobalMetrics()
// 	require.NoError(t, err)
// 	require.Equal(t, gm.DataRead+uint64(len("dir-1/file-1")), gmNew.DataRead)
// 	require.Equal(t, gm.FOPS[4]+1, gmNew.FOPS[4])

// 	_, err = nydusd.GetFilesMetrics("/")
// 	require.NoError(t, err)

// 	_, err = nydusd.GetBackendMetrics("/")
// 	require.NoError(t, err)

// 	_, err = nydusd.GetLatestFileMetrics()
// 	require.NoError(t, err)

// 	apms, err := nydusd.GetAccessPatternMetrics("/")
// 	require.NoError(t, err)
// 	require.NotEmpty(t, apms)

// 	apms, err = nydusd.GetAccessPatternMetrics("")
// 	require.NoError(t, err)
// 	require.NotEmpty(t, apms)

// 	apms, err = nydusd.GetAccessPatternMetrics("poison")
// 	require.NoError(t, err)
// 	require.Empty(t, apms)
// }

// func dropPageCache(t *testing.T) {
// 	f, err := os.OpenFile("/proc/sys/vm/drop_caches", os.O_WRONLY, 0644)
// 	require.NoError(t, err)
// 	defer f.Close()
// 	_, err = f.WriteString("3")
// 	require.NoError(t, err)
// }

// func accessMount(t *testing.T, mountPath string) {
// 	cmd := exec.Command("bash", "-c", fmt.Sprintf("find %s -type f -print0 | xargs -0 sha256sum 2>&1 > /dev/null", mountPath))
// 	cmd.Stderr = os.Stderr
// 	cmd.Stdout = os.Stdout
// 	err := cmd.Run()
// 	require.NoError(t, err)
// }

// func limitCPUMem(t *testing.T, pid int) {
// 	err := os.MkdirAll("/sys/fs/cgroup/cpu/default/nydusd", 0755)
// 	require.NoError(t, err)

// 	err = os.MkdirAll("/sys/fs/cgroup/memory/default/nydusd", 0755)
// 	require.NoError(t, err)

// 	period := 100000
// 	quota := 100000               // 1c
// 	memLimit := 512 * 1024 * 1024 // 1g

// 	// Set CPU limit
// 	err = os.WriteFile(path.Join("/sys/fs/cgroup/cpu/default/nydusd", "cpu.cfs_quota_us"), []byte(strconv.Itoa(quota)), 0644)
// 	require.NoError(t, err)
// 	err = os.WriteFile(path.Join("/sys/fs/cgroup/cpu/default/nydusd", "cpu.cfs_period_us"), []byte(strconv.Itoa(period)), 0644)
// 	require.NoError(t, err)

// 	// Set memory limit
// 	err = os.WriteFile(path.Join("/sys/fs/cgroup/memory/default/nydusd", "memory.limit_in_bytes"), []byte(strconv.Itoa(memLimit)), 0644)
// 	require.NoError(t, err)

// 	pidBytes := []byte(strconv.Itoa(pid))

// 	fmt.Println("pidBytes", string(pidBytes))

// 	err = os.WriteFile(path.Join("/sys/fs/cgroup/cpu/default/nydusd", "tasks"), pidBytes, 0644)
// 	require.NoError(t, err)

// 	err = os.WriteFile(path.Join("/sys/fs/cgroup/memory/default/nydusd", "tasks"), pidBytes, 0644)
// 	require.NoError(t, err)
// }

func (a *APIV1TestSuite) TestMultipleMounts1(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.Build.FSVersion = "5"
	ctx.Build.Compressor = "lz4_block"

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	config := tool.NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}
	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)

	// limitCPUMem(t, nydusd.Pid)

	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.EnablePrefetch = true
	config.PrefetchFiles = []string{"/"}
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode

	j := 0
	subMountPaths := make([]string, 200)
	for i := 0; i < 500; i++ {
		j++
		if j > 20 {
			j = 0
			// if i == 280 {
			// 	dropPageCache(t)
			// }
		}
		if subMountPaths[j] != "" {
			// fmt.Println("UN-MOUNT", subMountPaths[j])
			// time.Sleep(10 * time.Minute)
			// fmt.Println("UN-MOUNT", subMountPaths[j])
			nydusd.UmountByAPI(t, subMountPaths[j])
			// dropPageCache(t)
		}

		subPath := fmt.Sprintf("/sub-mount-%s", uuid.NewString())
		rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, uuid.NewString()))
		config.BootstrapPath = a.rootFsToRafs(t, ctx, rootFs)

		config.MountPath = subPath
		absMountPath := filepath.Join(ctx.Env.MountDir, config.MountPath)
		subMountPaths[j] = subPath

		nydusd.MountByAPI(t, config)
		// accessMount(t, absMountPath)
		tool.VerifyMount(t, rootFs.FileTree, absMountPath)
		daemonInfo := nydusd.GetDaemonInfoByAPI(t)
		fmt.Println("MOUNT:", subPath, "TOTAL:", len(daemonInfo.BackendCollection), "COUNT:", i+1)
	}
}

func (a *APIV1TestSuite) TestMultipleMounts2(t *testing.T) {
	ctx := tool.DefaultContext(t)
	ctx.Build.FSVersion = "5"
	ctx.Build.Compressor = "lz4_block"

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	config := tool.NydusdConfig{
		NydusdPath:  ctx.Binary.Nydusd,
		MountPath:   ctx.Env.MountDir,
		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
	}
	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)

	// limitCPUMem(t, nydusd.Pid)

	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	config.BackendType = "localfs"
	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
	config.EnablePrefetch = true
	config.PrefetchFiles = []string{"/"}
	config.BlobCacheDir = ctx.Env.CacheDir
	config.CacheType = ctx.Runtime.CacheType
	config.CacheCompressed = ctx.Runtime.CacheCompressed
	config.RafsMode = ctx.Runtime.RafsMode

	for i := 0; i < 300; i++ {
		rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, uuid.NewString()))
		config.BootstrapPath = a.rootFsToRafs(t, ctx, rootFs)

		subPath := fmt.Sprintf("/sub-mount-%d", i)
		config.MountPath = subPath
		absMountPath := filepath.Join(ctx.Env.MountDir, config.MountPath)
		daemonInfo := nydusd.GetDaemonInfoByAPI(t)
		fmt.Println("MOUNT:", subPath, "TOTAL:", len(daemonInfo.BackendCollection), "COUNT:", i+1)

		nydusd.MountByAPI(t, config)
		// if i == 280 {
		// 	dropPageCache(t)
		// }
		// accessMount(t, absMountPath)
		tool.VerifyMount(t, rootFs.FileTree, absMountPath)
		nydusd.UmountByAPI(t, config.MountPath)
	}
}

// func (a *APIV1TestSuite) TestPrefetch(t *testing.T) {

// 	ctx := tool.DefaultContext(t)

// 	ctx.PrepareWorkDir(t)
// 	defer ctx.Destroy(t)

// 	rootFs := texture.MakeLowerLayer(
// 		t,
// 		filepath.Join(ctx.Env.WorkDir, "root-fs"),
// 		texture.LargerFileMaker("large-blob.bin", 5))

// 	rafs := a.rootFsToRafs(t, ctx, rootFs)

// 	config := tool.NydusdConfig{
// 		NydusdPath:  ctx.Binary.Nydusd,
// 		MountPath:   ctx.Env.MountDir,
// 		APISockPath: filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
// 		ConfigPath:  filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
// 	}
// 	nydusd, err := tool.NewNydusd(config)
// 	require.NoError(t, err)

// 	err = nydusd.Mount()
// 	require.NoError(t, err)
// 	defer func() {
// 		if err := nydusd.Umount(); err != nil {
// 			log.L.WithError(err).Errorf("umount")
// 		}
// 	}()

// 	config.BootstrapPath = rafs
// 	config.MountPath = "/pseudo_fs_1"
// 	config.BackendType = "localfs"
// 	config.BackendConfig = fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir)
// 	config.EnablePrefetch = true
// 	config.PrefetchFiles = []string{"/"}
// 	config.BlobCacheDir = ctx.Env.CacheDir
// 	config.CacheType = ctx.Runtime.CacheType
// 	config.CacheCompressed = ctx.Runtime.CacheCompressed
// 	config.RafsMode = ctx.Runtime.RafsMode
// 	nydusd.MountByAPI(t, config)
// 	require.NoError(t, err)
// 	time.Sleep(time.Millisecond * 15)

// 	bcm, err := nydusd.GetBlobCacheMetrics("")
// 	require.NoError(t, err)
// 	require.Greater(t, bcm.PrefetchDataAmount, uint64(0))

// 	_, err = nydusd.GetBlobCacheMetrics("/pseudo_fs_1")
// 	require.NoError(t, err)
// }

func (a *APIV1TestSuite) rootFsToRafs(t *testing.T, ctx *tool.Context, rootFs *tool.Layer) string {
	digest := rootFs.Pack(t,
		converter.PackOption{
			BuilderPath: ctx.Binary.Builder,
			Compressor:  ctx.Build.Compressor,
			FsVersion:   ctx.Build.FSVersion,
			ChunkSize:   ctx.Build.ChunkSize,
		},
		ctx.Env.BlobDir)
	_, bootstrap := tool.MergeLayers(t, *ctx,
		converter.MergeOption{
			BuilderPath: ctx.Binary.Builder,
		},
		[]converter.Layer{
			{Digest: digest},
		})
	return bootstrap
}

// func (a *APIV1TestSuite) visit(path string) error {
// 	f, err := os.Open(path)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()

// 	io.ReadAll(f)

// 	return nil
// }

func TestAPI(t *testing.T) {
	test.Run(t, &APIV1TestSuite{})
}
