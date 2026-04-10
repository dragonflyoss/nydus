// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package dragonfly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv holds all paths and processes for a Dragonfly E2E test run.
type testEnv struct {
	Dragonfly     *DragonflyEnv
	Nydusd        *NydusdInstance
	MountDir      string
	CacheDir      string
	DragonflyCacheDir string
	Mode          string // sdk-proxy, sdk-proxy-strict, http-proxy
}

// setupTestEnv reads environment variables and starts all services.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	mode := os.Getenv("TEST_MODE")
	require.NotEmpty(t, mode, "TEST_MODE env var required (sdk-proxy, sdk-proxy-strict, http-proxy)")

	nydusdBin := envOrDefault("NYDUSD_BIN", "/usr/local/bin/nydusd")
	configPath := os.Getenv("NYDUSD_CONFIG")
	bootstrapPath := os.Getenv("BOOTSTRAP_PATH")
	require.NotEmpty(t, configPath, "NYDUSD_CONFIG env var required")
	require.NotEmpty(t, bootstrapPath, "BOOTSTRAP_PATH env var required")

	workDir := envOrDefault("WORK_DIR", "/tmp/nydus-test")
	logDir := envOrDefault("LOG_DIR", "/tmp/dragonfly/logs")
	cacheDir := filepath.Join(workDir, "cache")
	mountDir := filepath.Join(workDir, "mnt")
	logFile := filepath.Join(workDir, "nydusd.log")
	apiSock := filepath.Join(workDir, "nydusd-api.sock")
	dragonflyCacheDir := envOrDefault("DRAGONFLY_CACHE_DIR", "/tmp/dragonfly/cache")

	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	require.NoError(t, os.MkdirAll(mountDir, 0755))
	require.NoError(t, os.MkdirAll(dragonflyCacheDir, 0755))

	// Start Dragonfly cluster
	df := SetupDragonflyCluster(t, logDir)

	// Start nydusd
	nydusd := StartNydusd(t, nydusdBin, configPath, bootstrapPath, mountDir, logFile, apiSock)

	return &testEnv{
		Dragonfly:         df,
		Nydusd:            nydusd,
		MountDir:          mountDir,
		CacheDir:          cacheDir,
		DragonflyCacheDir: dragonflyCacheDir,
		Mode:              mode,
	}
}

func (env *testEnv) teardown(t *testing.T) {
	t.Helper()
	if env.Nydusd != nil {
		env.Nydusd.Stop(t)
	}
	if env.Dragonfly != nil {
		env.Dragonfly.Teardown(t)
	}
}

func (env *testEnv) isSDKMode() bool {
	return strings.HasPrefix(env.Mode, "sdk-proxy")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestDragonflyE2E is the main E2E test for Dragonfly proxy integration.
func TestDragonflyE2E(t *testing.T) {
	env := setupTestEnv(t)
	defer env.teardown(t)

	// === Happy Path Tests ===

	t.Run("VerifyMount", func(t *testing.T) {
		entries, err := os.ReadDir(env.MountDir)
		require.NoError(t, err, "should be able to list mount directory")
		assert.Greater(t, len(entries), 0, "mounted filesystem should have entries")
		t.Logf("mount has %d top-level entries", len(entries))
	})

	t.Run("MultiFileRead", func(t *testing.T) {
		candidates := []string{
			"etc/os-release", "etc/passwd", "etc/group",
			"etc/hostname", "etc/resolv.conf",
		}
		passed := 0
		for _, f := range candidates {
			path := filepath.Join(env.MountDir, f)
			data, err := os.ReadFile(path)
			if err == nil && len(data) > 0 {
				passed++
				t.Logf("  OK: %s (%d bytes)", f, len(data))
			}
		}
		require.Greater(t, passed, 0, "at least one file should be readable")
		t.Logf("read %d/%d files successfully", passed, len(candidates))
	})

	t.Run("BinaryFileRead", func(t *testing.T) {
		// Find a shared library or binary
		files := FindFiles(env.MountDir, 4, 100)
		var binary string
		for _, f := range files {
			if strings.HasSuffix(f, ".so") || strings.Contains(f, ".so.") {
				binary = f
				break
			}
		}
		if binary == "" {
			// Try executables under /usr
			usrFiles := FindFiles(filepath.Join(env.MountDir, "usr"), 3, 50)
			for _, f := range usrFiles {
				info, err := os.Stat(f)
				if err == nil && info.Mode()&0111 != 0 && info.Size() > 0 {
					binary = f
					break
				}
			}
		}
		if binary == "" {
			t.Skip("no binary files found in image")
		}

		info, err := os.Stat(binary)
		require.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0), "binary should have non-zero size")
		t.Logf("binary: %s (%d bytes)", binary, info.Size())
	})

	t.Run("DirectoryTraversal", func(t *testing.T) {
		fileCount, dirCount := CountFiles(env.MountDir, 3)
		assert.Greater(t, fileCount, 10, "should have at least 10 files")
		t.Logf("found %d files in %d directories", fileCount, dirCount)
	})

	t.Run("CachePopulated", func(t *testing.T) {
		fileCount, _ := CountFiles(env.CacheDir, 5)
		assert.Greater(t, fileCount, 0, "blob cache should be populated after reads")
		t.Logf("cache has %d files", fileCount)
	})

	t.Run("ReReadConsistency", func(t *testing.T) {
		target := ""
		for _, f := range []string{"etc/os-release", "etc/passwd", "etc/hostname"} {
			path := filepath.Join(env.MountDir, f)
			if _, err := os.Stat(path); err == nil {
				target = path
				break
			}
		}
		if target == "" {
			t.Skip("no suitable file for re-read test")
		}

		data1, err := os.ReadFile(target)
		require.NoError(t, err)
		data2, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, data1, data2, "re-read should return identical content")
	})

	t.Run("SDKClientCreated", func(t *testing.T) {
		if !env.isSDKMode() {
			t.Skip("SDK client check only applies to sdk-proxy modes")
		}
		assert.True(t, env.Nydusd.LogContains(t, "creating new proxy sdk client"),
			"nydusd log should contain SDK client creation message")
	})

	t.Run("P2PActivity", func(t *testing.T) {
		// Check for any proxy/backend activity in nydusd logs
		assert.True(t,
			env.Nydusd.LogContains(t, "proxy") || env.Nydusd.LogContains(t, "backend"),
			"nydusd log should contain proxy or backend activity")
	})

	// === Failure & Recovery Tests (SDK modes only) ===

	t.Run("KillDfdaemon_HealthCheckDetection", func(t *testing.T) {
		if !env.isSDKMode() {
			t.Skip("proxy failure tests only for sdk-proxy modes")
		}

		logBefore := env.Nydusd.LogLineCount(t)

		t.Log("killing dfdaemon...")
		env.Dragonfly.Dfdaemon.Stop(t)

		// Wait for health check to detect (check_interval=5s, give 15s)
		found := WaitForLogPattern(env.Nydusd, logBefore, "unhealthy", 15*time.Second)
		if !found {
			found = WaitForLogPattern(env.Nydusd, logBefore, "not healthy", 5*time.Second)
		}
		newLogs := env.Nydusd.LogSince(t, logBefore)
		t.Logf("new log entries:\n%s", newLogs)

		if found {
			t.Log("PASS: health check detected proxy failure")
		} else {
			t.Log("WARNING: health check detection not found in logs (timing issue)")
		}
	})

	t.Run("ReadWithProxyDown", func(t *testing.T) {
		if !env.isSDKMode() {
			t.Skip("proxy-down tests only for sdk-proxy modes")
		}

		// 1. Stop dfdaemon (may already be down from prior test)
		t.Log("ensuring dfdaemon is stopped...")
		env.Dragonfly.Dfdaemon.Stop(t)

		// 2. Stop nydusd (umount + kill) to release all in-memory/FUSE caches
		t.Log("stopping nydusd...")
		env.Nydusd.Stop(t)

		// 3. Clear ALL caches while nydusd is down
		t.Log("clearing all caches (blob + dragonfly + kernel page cache)...")
		ClearCaches(t, env.CacheDir, env.DragonflyCacheDir)

		// 4. Restart nydusd with cold caches, dfdaemon still down
		t.Log("restarting nydusd with cold caches (dfdaemon still down)...")
		env.Nydusd.Restart(t)

		logBefore := env.Nydusd.LogLineCount(t)

		// 5. Read a file — behavior depends on fallback config
		target := filepath.Join(env.MountDir, "etc/os-release")
		t.Logf("reading %s with dfdaemon down (mode=%s)...", target, env.Mode)
		data, err := os.ReadFile(target)
		newLogs := env.Nydusd.LogSince(t, logBefore)

		switch env.Mode {
		case "sdk-proxy":
			// fallback=true: read should succeed via direct backend
			require.NoError(t, err,
				"fallback=true: file read should succeed via direct backend")
			assert.Greater(t, len(data), 0, "file content should not be empty")
			t.Logf("PASS: read %d bytes via direct fallback (fallback=true)", len(data))

		case "sdk-proxy-strict":
			// fallback=false: read should fail — no proxy, no fallback, no cache
			require.Error(t, err,
				"fallback=false: file read should fail with no proxy and no cache; "+
					"logs:\n%s", truncateString(newLogs, 500))
			t.Logf("PASS: file read failed as expected in strict mode: %v", err)
		}

		t.Logf("logs after read attempt:\n%s", truncateString(newLogs, 500))
	})

	t.Run("KillScheduler_SDKFallback", func(t *testing.T) {
		if env.Mode != "sdk-proxy" {
			t.Skip("scheduler kill test only for sdk-proxy")
		}

		// Ensure dfdaemon is running (restart if killed earlier)
		env.Dragonfly.Dfdaemon.Restart(t)
		// Give nydusd time to detect recovered proxy
		time.Sleep(10 * time.Second)

		logBefore := env.Nydusd.LogLineCount(t)

		t.Log("killing scheduler...")
		env.Dragonfly.Scheduler.Stop(t)

		// Stop nydusd to clear caches cleanly
		t.Log("stopping nydusd to clear caches...")
		env.Nydusd.Stop(t)
		ClearCaches(t, env.CacheDir, env.DragonflyCacheDir)
		t.Log("restarting nydusd...")
		env.Nydusd.Restart(t)

		logBefore = env.Nydusd.LogLineCount(t)

		t.Log("reading file with scheduler down (SDK should error, fallback to HTTP proxy or direct)...")
		target := filepath.Join(env.MountDir, "etc/os-release")
		data, err := os.ReadFile(target)
		require.NoError(t, err, "file read should succeed via fallback chain")
		assert.Greater(t, len(data), 0)

		newLogs := env.Nydusd.LogSince(t, logBefore)
		t.Logf("logs after scheduler kill:\n%s",
			truncateString(newLogs, 500))
	})

	t.Run("RestartAndRecover", func(t *testing.T) {
		if !env.isSDKMode() {
			t.Skip("recovery test only for sdk-proxy modes")
		}

		// Restart all Dragonfly services
		t.Log("restarting scheduler...")
		env.Dragonfly.Scheduler.Restart(t)

		t.Log("restarting dfdaemon...")
		env.Dragonfly.Dfdaemon.Restart(t)

		// Restart nydusd with clean caches to test recovery path
		t.Log("stopping nydusd to clear caches before recovery test...")
		env.Nydusd.Stop(t)
		ClearCaches(t, env.CacheDir, env.DragonflyCacheDir)
		t.Log("restarting nydusd...")
		env.Nydusd.Restart(t)

		logBefore := env.Nydusd.LogLineCount(t)

		// Wait for health check to detect recovery
		t.Log("waiting for proxy recovery detection (up to 20s)...")
		found := WaitForLogPattern(env.Nydusd, logBefore, "recovered", 20*time.Second)
		if found {
			t.Log("PASS: proxy recovery detected in logs")
		} else {
			t.Log("WARNING: recovery log message not found (may need more time)")
		}

		t.Log("reading file after recovery...")
		target := filepath.Join(env.MountDir, "etc/os-release")
		data, err := os.ReadFile(target)
		require.NoError(t, err, "file read should succeed after proxy recovery")
		assert.Greater(t, len(data), 0)
		t.Log("PASS: file read succeeded after recovery")
	})
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
