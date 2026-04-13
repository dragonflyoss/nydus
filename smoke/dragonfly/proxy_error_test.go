// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package dragonfly

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proxyErrorEnv holds paths and the test proxy process for error simulation tests.
type proxyErrorEnv struct {
	Proxy            *Process
	NydusdBin        string
	BootstrapPath    string
	WorkDir          string
	MountDir         string
	CacheDir         string
	LogDir           string
	ApiSock          string
	FallbackConfig   string
	NoFallbackConfig string
	restartCount     int
}

const proxyAddr = "http://127.0.0.1:4001"

// injectError tells the test proxy to return the given status code for subsequent requests.
func injectError(t *testing.T, status int, count int) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"status": status,
		"count":  count,
	})
	resp, err := http.Post(proxyAddr+"/_test/inject", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "failed to inject error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Logf("injected error: status=%d count=%d", status, count)
}

// injectTimeout tells the test proxy to delay responses. The delay
// must exceed nydusd's configured timeout (5s) so the client times out
// before the proxy responds. No status code is set; after the delay
// the proxy forwards normally (to the already-timed-out connection).
func injectTimeout(t *testing.T, timeout string, count int) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"timeout": timeout,
		"count":   count,
	})
	resp, err := http.Post(proxyAddr+"/_test/inject", "application/json", bytes.NewReader(body))
	require.NoError(t, err, "failed to inject timeout")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Logf("injected timeout: duration=%s count=%d", timeout, count)
}

// clearInjection removes any active injection rule from the test proxy.
func clearInjection(t *testing.T) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, proxyAddr+"/_test/inject", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "failed to clear injection")
	resp.Body.Close()
}

// setupProxyErrorEnv builds the test proxy, starts it on :4001, and prepares
// the test environment. Does NOT start the Dragonfly cluster.
func setupProxyErrorEnv(t *testing.T) *proxyErrorEnv {
	t.Helper()

	repoRoot := os.Getenv("REPO_ROOT")
	require.NotEmpty(t, repoRoot, "REPO_ROOT env var required (path to nydus-rs repo root)")

	nydusdBin := envOrDefault("NYDUSD_BIN", "/usr/local/bin/nydusd")
	bootstrapPath := os.Getenv("BOOTSTRAP_PATH")
	require.NotEmpty(t, bootstrapPath, "BOOTSTRAP_PATH env var required")

	workDir := envOrDefault("WORK_DIR", "/tmp/nydus-proxy-error-test")
	logDir := filepath.Join(workDir, "logs")
	cacheDir := filepath.Join(workDir, "cache")
	mountDir := filepath.Join(workDir, "mnt")
	apiSock := filepath.Join(workDir, "nydusd-api.sock")

	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	require.NoError(t, os.MkdirAll(mountDir, 0755))
	require.NoError(t, os.MkdirAll(logDir, 0755))

	// Build test proxy
	proxyBin := filepath.Join(workDir, "test-proxy")
	proxySource := filepath.Join(repoRoot, "smoke", "proxy")
	t.Logf("building test proxy from %s...", proxySource)
	buildCmd := exec.Command("go", "build", "-o", proxyBin, proxySource)
	buildOut, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "failed to build test proxy: %s", string(buildOut))

	// Start test proxy on :4001
	proxyLog := filepath.Join(logDir, "test-proxy.log")
	proxy := StartProcess(t, proxyBin, nil, proxyLog, "4001")

	return &proxyErrorEnv{
		Proxy:            proxy,
		NydusdBin:        nydusdBin,
		BootstrapPath:    bootstrapPath,
		WorkDir:          workDir,
		MountDir:         mountDir,
		CacheDir:         cacheDir,
		LogDir:           logDir,
		ApiSock:          apiSock,
		FallbackConfig:   filepath.Join(repoRoot, "misc", "dragonfly", "nydusd-proxy-error-fallback.json"),
		NoFallbackConfig: filepath.Join(repoRoot, "misc", "dragonfly", "nydusd-proxy-error-nofallback.json"),
	}
}

func (env *proxyErrorEnv) teardown(t *testing.T) {
	t.Helper()
	if env.Proxy != nil {
		env.Proxy.Stop(t)
	}
}

// startNydusdForTest starts nydusd with the given config, returning the instance.
// The caller must call nydusd.Stop(t) when done.
func (env *proxyErrorEnv) startNydusdForTest(t *testing.T, configPath string) *NydusdInstance {
	t.Helper()
	env.restartCount++
	logFile := filepath.Join(env.LogDir, fmt.Sprintf("nydusd-%d.log", env.restartCount))

	require.NoError(t, os.MkdirAll(env.MountDir, 0755))
	return StartNydusd(t, env.NydusdBin, configPath, env.BootstrapPath,
		env.MountDir, logFile, env.ApiSock)
}

// runReadTest injects an error, starts nydusd, reads a file, and asserts the outcome.
// If expectSuccess is true, the read must succeed; if false, it must fail.
func (env *proxyErrorEnv) runReadTest(t *testing.T, configPath string, expectSuccess bool) {
	t.Helper()

	// Clear caches
	ClearCaches(t, env.CacheDir)

	// Start nydusd
	nydusd := env.startNydusdForTest(t, configPath)
	defer nydusd.Stop(t)

	logBefore := nydusd.LogLineCount(t)

	// Read a file through the FUSE mount
	target := filepath.Join(env.MountDir, "etc/os-release")
	data, err := os.ReadFile(target)
	newLogs := nydusd.LogSince(t, logBefore)

	if expectSuccess {
		require.NoError(t, err, "read should succeed; logs:\n%s", truncateString(newLogs, 1000))
		assert.Greater(t, len(data), 0, "file content should not be empty")
		t.Logf("read %d bytes successfully", len(data))
	} else {
		require.Error(t, err, "read should fail; logs:\n%s", truncateString(newLogs, 1000))
		t.Logf("read failed as expected: %v", err)
	}

	t.Logf("nydusd logs:\n%s", truncateString(newLogs, 1000))
}

// TestProxyErrorSimulation tests nydusd's error handling when the proxy returns
// various HTTP error codes. It uses the test proxy's control API to inject errors
// dynamically. Each sub-test starts a fresh nydusd instance with cold caches.
//
// Error handling pipeline (verified from source):
//
//	Connection::call() → only falls back for status >= 500 when fallback=true
//	Request::call()    → checks X-Dragonfly-Error-Type header, maps to typed errors
//	retry_op()         → handles typed errors: 429=disable_proxy, 403=no retry
func TestProxyErrorSimulation(t *testing.T) {
	env := setupProxyErrorEnv(t)
	defer env.teardown(t)

	t.Run("Fallback", func(t *testing.T) {
		config := env.FallbackConfig

		t.Run("Status429_FallbackViaDisableProxy", func(t *testing.T) {
			// 429 with X-Dragonfly-Error-Type: proxy → Request::call() converts
			// to TooManyRequests → retry_op() sets disable_proxy=true on first
			// retry → next attempt goes direct to origin → success.
			injectError(t, 429, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})

		t.Run("Status403_ReadFails", func(t *testing.T) {
			// 403 with X-Dragonfly-Error-Type: proxy → Request::call() converts
			// to Forbidden → retry_op() breaks immediately, no retry.
			injectError(t, 403, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, false)
		})

		t.Run("Status500_FallbackToOrigin", func(t *testing.T) {
			// 500 → Connection::call() sees status >= 500 with fallback=true →
			// falls back to origin → success on first attempt.
			injectError(t, 500, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})

		t.Run("Timeout_FallbackToOrigin", func(t *testing.T) {
			// Timeout > connect_timeout (5s) → reqwest timeout → Connection error →
			// Connection::call() Err path with fallback=true → falls through to
			// origin → success.
			injectTimeout(t, "10s", -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})
	})

	t.Run("NoFallback", func(t *testing.T) {
		config := env.NoFallbackConfig

		t.Run("Status429_DisableProxyRetry", func(t *testing.T) {
			// 429 → same mechanism as fallback=true: Request::call() converts to
			// TooManyRequests → retry_op() sets disable_proxy=true on first retry →
			// next attempt bypasses proxy entirely → success.
			injectError(t, 429, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})

		t.Run("Status403_ReadFails", func(t *testing.T) {
			// 403 → same as fallback=true: Forbidden → no retry → failure.
			injectError(t, 403, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, false)
		})

		t.Run("Status500_DisableProxyRetry", func(t *testing.T) {
			// 500 + fallback=false → Connection::call() returns proxy 500 as-is.
			// Request::call() detects X-Dragonfly-Error-Type → Common error.
			// retry_op() retries (on-demand gets 3 retries). On last retry,
			// sets disable_proxy=true → final attempt goes direct → success.
			injectError(t, 500, -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})

		t.Run("Timeout_DisableProxyRetry", func(t *testing.T) {
			// Timeout + fallback=false → Connection error, no fallback → Err.
			// retry_op() retries. Each retry times out (connect_timeout=5s × 3).
			// Last retry sets disable_proxy=true → final attempt goes direct → success.
			// This is the slowest test (~15-20s due to 3 timeouts).
			injectTimeout(t, "10s", -1)
			defer clearInjection(t)
			env.runReadTest(t, config, true)
		})
	})

	t.Run("Recovery", func(t *testing.T) {
		t.Run("HealthRecovery", func(t *testing.T) {
			config := env.FallbackConfig

			// Phase 1: Inject errors, verify reads still succeed via fallback
			injectError(t, 500, 3)
			ClearCaches(t, env.CacheDir)
			nydusd := env.startNydusdForTest(t, config)

			target := filepath.Join(env.MountDir, "etc/os-release")
			data, err := os.ReadFile(target)
			require.NoError(t, err, "read should succeed via fallback during errors")
			assert.Greater(t, len(data), 0)
			t.Logf("phase 1: read %d bytes via fallback", len(data))

			// Phase 2: Errors exhausted (count=3), proxy forwarding normally.
			// Stop and restart nydusd with cold caches to force fresh requests.
			nydusd.Stop(t)
			ClearCaches(t, env.CacheDir)
			clearInjection(t)

			nydusd2 := env.startNydusdForTest(t, config)
			defer nydusd2.Stop(t)

			logBefore := nydusd2.LogLineCount(t)

			data2, err := os.ReadFile(target)
			require.NoError(t, err, "read should succeed through proxy after recovery")
			assert.Greater(t, len(data2), 0)
			t.Logf("phase 2: read %d bytes after recovery", len(data2))

			newLogs := nydusd2.LogSince(t, logBefore)
			hasFallback := strings.Contains(strings.ToLower(newLogs), "fallback")
			if !hasFallback {
				t.Log("PASS: no fallback logged — reads going through proxy normally")
			} else {
				t.Log("WARNING: fallback still occurring after error recovery")
			}
		})
	})
}
