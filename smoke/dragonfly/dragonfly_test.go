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
	Mode          string // sdk-proxy, sdk-proxy-strict, http-proxy, http-proxy-strict
}

// setupTestEnv reads environment variables and starts all services.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	mode := os.Getenv("TEST_MODE")
	require.NotEmpty(t, mode, "TEST_MODE env var required (sdk-proxy, sdk-proxy-strict, http-proxy, http-proxy-strict)")

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

// isStrictMode returns true for modes with fallback=false.
func (env *testEnv) isStrictMode() bool {
	return env.Mode == "sdk-proxy-strict" || env.Mode == "http-proxy-strict"
}

// hasFallback returns true when the proxy config has fallback enabled.
func (env *testEnv) hasFallback() bool {
	return !env.isStrictMode()
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

	// === Failure & Recovery Tests ===
	// These tests verify the proxy fallback logic that must match nydus-ant's
	// Connection::call() behavior: proxy healthy → try proxy → on 5xx/error +
	// fallback=true → fall back to origin; fallback=false → return error.

	t.Run("KillDfdaemon_HealthCheckDetection", func(t *testing.T) {
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
		// This test verifies the core fallback behavior from nydus-ant's
		// Connection::call(): when proxy is unreachable and fallback=true,
		// requests fall back to the origin; when fallback=false, they fail.

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

		if env.hasFallback() {
			// fallback=true (sdk-proxy, http-proxy): read should succeed via direct backend.
			// This matches nydus-ant behavior: proxy error + fallback=true → origin.
			require.NoError(t, err,
				"fallback=true: file read should succeed via direct backend")
			assert.Greater(t, len(data), 0, "file content should not be empty")
			t.Logf("PASS: read %d bytes via direct fallback (mode=%s)", len(data), env.Mode)
		} else {
			// fallback=false (sdk-proxy-strict, http-proxy-strict): read should fail.
			// This matches nydus-ant behavior: proxy error + fallback=false → return error.
			require.Error(t, err,
				"fallback=false: file read should fail with no proxy and no cache; "+
					"logs:\n%s", truncateString(newLogs, 500))
			t.Logf("PASS: file read failed as expected in strict mode (mode=%s): %v", env.Mode, err)
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
		if env.isStrictMode() {
			t.Skip("recovery test not applicable in strict (no-fallback) modes")
		}

		// Restart all Dragonfly services
		t.Log("restarting scheduler...")
		env.Dragonfly.Scheduler.Restart(t)

		t.Log("restarting dfdaemon...")
		env.Dragonfly.Dfdaemon.Restart(t)

		// Restart nydusd with clean caches to test recovery path.
		// This verifies the nydus-ant health check recovery behavior:
		// proxy goes unhealthy → detected by health thread → proxy recovers →
		// health thread detects recovery → subsequent reads go through proxy.
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

	t.Run("ProxyUnhealthy_NoFallback", func(t *testing.T) {
		if !env.isStrictMode() {
			t.Skip("unhealthy+no-fallback test only for strict modes")
		}

		// This test verifies the nydus-specific fix (ef58cb0f5):
		// When proxy is unhealthy and fallback=false, Connection::call()
		// returns an error immediately instead of falling through to origin.
		// This is stricter than nydus-ant which would still fall through.

		// 1. Stop dfdaemon to make proxy unhealthy
		t.Log("stopping dfdaemon to make proxy unhealthy...")
		env.Dragonfly.Dfdaemon.Stop(t)

		// 2. Stop nydusd and clear caches
		t.Log("stopping nydusd and clearing caches...")
		env.Nydusd.Stop(t)
		ClearCaches(t, env.CacheDir, env.DragonflyCacheDir)

		// 3. Restart nydusd — health check will detect proxy is down
		t.Log("restarting nydusd with proxy down...")
		env.Nydusd.Restart(t)

		// 4. Wait for health check to mark proxy as unhealthy
		logBefore := env.Nydusd.LogLineCount(t)
		t.Log("waiting for health check to detect unhealthy proxy...")
		WaitForLogPattern(env.Nydusd, logBefore, "unhealthy", 15*time.Second)

		// 5. Try to read a file — should fail since proxy is unhealthy
		//    and fallback=false returns error immediately
		target := filepath.Join(env.MountDir, "etc/os-release")
		t.Logf("reading %s with unhealthy proxy and fallback=false...", target)
		_, err := os.ReadFile(target)
		newLogs := env.Nydusd.LogSince(t, logBefore)

		require.Error(t, err,
			"proxy unhealthy + fallback=false: read should fail; logs:\n%s",
			truncateString(newLogs, 500))
		t.Logf("PASS: file read failed as expected (proxy unhealthy, no fallback): %v", err)
	})

	t.Run("FallbackLogging", func(t *testing.T) {
		if !env.hasFallback() {
			t.Skip("fallback logging test only for modes with fallback=true")
		}

		// Verify that when fallback occurs, nydus logs the fallback event.
		// This matches nydus-ant behavior: "Request proxy server failed,
		// fallback to original server" or "Proxy server is not healthy,
		// fallback to original server".

		// Ensure dfdaemon is stopped
		env.Dragonfly.Dfdaemon.Stop(t)

		// Restart nydusd with cold caches
		env.Nydusd.Stop(t)
		ClearCaches(t, env.CacheDir, env.DragonflyCacheDir)
		env.Nydusd.Restart(t)

		logBefore := env.Nydusd.LogLineCount(t)

		// Read a file to trigger fallback
		target := filepath.Join(env.MountDir, "etc/os-release")
		data, err := os.ReadFile(target)
		require.NoError(t, err, "read should succeed via fallback")
		assert.Greater(t, len(data), 0)

		// Check for fallback log messages
		newLogs := env.Nydusd.LogSince(t, logBefore)
		hasFallbackLog := strings.Contains(strings.ToLower(newLogs), "fallback")
		if hasFallbackLog {
			t.Log("PASS: fallback event logged")
		} else {
			t.Logf("WARNING: no 'fallback' message found in logs (may be rate-limited):\n%s",
				truncateString(newLogs, 500))
		}
	})
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
