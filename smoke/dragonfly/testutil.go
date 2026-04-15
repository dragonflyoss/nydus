// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package dragonfly provides E2E test utilities for Dragonfly proxy integration.
package dragonfly

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Process wraps an OS process with port/log tracking for service management.
type Process struct {
	Name    string
	Cmd     *exec.Cmd
	PidFile string
	LogFile string
	Port    string
}

// StartProcess launches a binary with the given args, logging stdout/stderr to logFile.
// It waits for the specified port to become available before returning.
func StartProcess(t *testing.T, name string, args []string, logFile string, port string) *Process {
	t.Helper()

	f, err := os.Create(logFile)
	require.NoError(t, err, "create log file for %s", name)

	cmd := exec.Command(name, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Start()
	require.NoError(t, err, "start %s", name)

	pidFile := logFile + ".pid"
	err = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644)
	require.NoError(t, err, "write pid file for %s", name)

	if port != "" {
		WaitForPort(t, port, 60*time.Second)
	}

	t.Logf("%s started (PID: %d, port: %s)", name, cmd.Process.Pid, port)
	return &Process{
		Name:    name,
		Cmd:     cmd,
		PidFile: pidFile,
		LogFile: logFile,
		Port:    port,
	}
}

// Stop kills the process and waits for its port to close.
func (p *Process) Stop(t *testing.T) {
	t.Helper()
	if p.Cmd == nil || p.Cmd.Process == nil {
		return
	}
	t.Logf("stopping %s (PID: %d)", p.Name, p.Cmd.Process.Pid)
	_ = p.Cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.Cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.Cmd.Process.Kill()
		<-done
	}
	if p.Port != "" {
		WaitForPortClosed(t, p.Port, 15*time.Second)
	}
	t.Logf("%s stopped", p.Name)
}

// Restart stops and restarts the process with the same arguments.
func (p *Process) Restart(t *testing.T) {
	t.Helper()
	args := p.Cmd.Args[1:] // skip binary name
	name := p.Cmd.Path
	logFile := p.LogFile + ".restart"
	port := p.Port

	p.Stop(t)

	restarted := StartProcess(t, name, args, logFile, port)
	*p = *restarted
}

// NydusdInstance wraps a running nydusd process with mount/config paths.
type NydusdInstance struct {
	Process       *Process
	MountDir      string
	ConfigPath    string
	LogFile       string
	BinPath       string
	BootstrapPath string
	ApiSock       string
	restartCount  int
}

// StartNydusd launches nydusd with the given config and bootstrap, mounting at mountDir.
func StartNydusd(t *testing.T, nydusdBin, configPath, bootstrapPath, mountDir, logFile, apiSock string) *NydusdInstance {
	t.Helper()

	require.NoError(t, os.MkdirAll(mountDir, 0755))

	args := []string{
		"--config", configPath,
		"--mountpoint", mountDir,
		"--bootstrap", bootstrapPath,
		"--log-level", "info",
		"--log-file", logFile,
		"--apisock", apiSock,
	}

	f, err := os.Create(logFile + ".stdout")
	require.NoError(t, err)

	cmd := exec.Command(nydusdBin, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	require.NoError(t, err, "start nydusd")

	t.Logf("nydusd started (PID: %d)", cmd.Process.Pid)

	WaitForMount(t, mountDir, 30*time.Second)

	return &NydusdInstance{
		Process: &Process{
			Name:    "nydusd",
			Cmd:     cmd,
			LogFile: logFile,
		},
		MountDir:      mountDir,
		ConfigPath:    configPath,
		LogFile:       logFile,
		BinPath:       nydusdBin,
		BootstrapPath: bootstrapPath,
		ApiSock:       apiSock,
	}
}

// Stop unmounts and kills nydusd.
func (n *NydusdInstance) Stop(t *testing.T) {
	t.Helper()
	_ = exec.Command("umount", n.MountDir).Run()
	if n.Process != nil {
		n.Process.Stop(t)
	}
}

// Restart stops nydusd, then starts it again with the same configuration.
// The log file is suffixed with .restart-N to preserve previous logs.
func (n *NydusdInstance) Restart(t *testing.T) {
	t.Helper()
	n.restartCount++
	logFile := fmt.Sprintf("%s.restart-%d", n.LogFile, n.restartCount)

	n.Stop(t)
	require.NoError(t, os.MkdirAll(n.MountDir, 0755))

	restarted := StartNydusd(t, n.BinPath, n.ConfigPath, n.BootstrapPath,
		n.MountDir, logFile, n.ApiSock)
	// Preserve the original LogFile path for log queries and restart count
	restarted.LogFile = logFile
	restarted.restartCount = n.restartCount
	*n = *restarted
}

// LogLineCount returns the current number of lines in the nydusd log file.
func (n *NydusdInstance) LogLineCount(t *testing.T) int {
	t.Helper()
	f, err := os.Open(n.LogFile)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count
}

// LogSince returns log lines from the given line number onwards.
func (n *NydusdInstance) LogSince(t *testing.T, fromLine int) string {
	t.Helper()
	f, err := os.Open(n.LogFile)
	if err != nil {
		return ""
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum > fromLine {
			lines = append(lines, scanner.Text())
		}
	}
	return strings.Join(lines, "\n")
}

// LogContains checks if the nydusd log contains the given pattern (case-insensitive).
func (n *NydusdInstance) LogContains(t *testing.T, pattern string) bool {
	t.Helper()
	data, err := os.ReadFile(n.LogFile)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), strings.ToLower(pattern))
}

// DragonflyEnv represents a running Dragonfly cluster for testing.
type DragonflyEnv struct {
	Manager   *Process
	Scheduler *Process
	Dfdaemon  *Process
	LogDir    string
}

// SetupDragonflyCluster starts Manager, Scheduler, and dfdaemon.
func SetupDragonflyCluster(t *testing.T, logDir string) *DragonflyEnv {
	t.Helper()

	require.NoError(t, os.MkdirAll(logDir, 0755))

	managerConfig := os.Getenv("MANAGER_CONFIG")
	schedulerConfig := os.Getenv("SCHEDULER_CONFIG")
	dfdaemonConfig := os.Getenv("DFDAEMON_CONFIG")

	require.NotEmpty(t, managerConfig, "MANAGER_CONFIG env var required")
	require.NotEmpty(t, schedulerConfig, "SCHEDULER_CONFIG env var required")
	require.NotEmpty(t, dfdaemonConfig, "DFDAEMON_CONFIG env var required")

	t.Log("Starting Dragonfly Manager...")
	manager := StartProcess(t, "manager",
		[]string{"--config", managerConfig},
		filepath.Join(logDir, "manager.log"), "8080",
	)

	t.Log("Starting Dragonfly Scheduler...")
	scheduler := StartProcess(t, "scheduler",
		[]string{"--config", schedulerConfig},
		filepath.Join(logDir, "scheduler.log"), "8002",
	)

	t.Log("Starting Dragonfly dfdaemon...")
	dfdaemon := StartProcess(t, "dfdaemon",
		[]string{"--config", dfdaemonConfig},
		filepath.Join(logDir, "dfdaemon.log"), "4001",
	)

	return &DragonflyEnv{
		Manager:   manager,
		Scheduler: scheduler,
		Dfdaemon:  dfdaemon,
		LogDir:    logDir,
	}
}

// Teardown stops all Dragonfly services.
func (env *DragonflyEnv) Teardown(t *testing.T) {
	t.Helper()
	if env.Dfdaemon != nil {
		env.Dfdaemon.Stop(t)
	}
	if env.Scheduler != nil {
		env.Scheduler.Stop(t)
	}
	if env.Manager != nil {
		env.Manager.Stop(t)
	}
}

// --- Utility functions ---

// WaitForPort blocks until a TCP connection can be made to localhost:port.
func WaitForPort(t *testing.T, port string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("port %s did not become available within %s", port, timeout)
}

// WaitForPortClosed blocks until the port is no longer accepting connections.
func WaitForPortClosed(t *testing.T, port string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 500*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		time.Sleep(time.Second)
	}
	t.Fatalf("port %s did not close within %s", port, timeout)
}

// WaitForMount blocks until the given path is a mountpoint.
func WaitForMount(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("mountpoint", "-q", path).CombinedOutput()
		if err == nil {
			return
		}
		_ = out
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not become a mountpoint within %s", path, timeout)
}

// ClearCaches removes blob cache files, dragonfly cache, and drops kernel page cache.
func ClearCaches(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	// Drop kernel page cache
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0644)
}

// ParseCacheDir extracts the blobcache work_dir from a nydusd JSON config file.
func ParseCacheDir(t *testing.T, configPath string) string {
	t.Helper()
	data, err := os.ReadFile(configPath)
	require.NoError(t, err, "read nydusd config %s", configPath)

	var cfg struct {
		Device struct {
			Cache struct {
				Config struct {
					WorkDir string `json:"work_dir"`
				} `json:"config"`
			} `json:"cache"`
		} `json:"device"`
	}
	require.NoError(t, json.Unmarshal(data, &cfg), "parse nydusd config %s", configPath)
	require.NotEmpty(t, cfg.Device.Cache.Config.WorkDir, "work_dir not found in %s", configPath)
	return cfg.Device.Cache.Config.WorkDir
}

// CountFiles counts regular files under root up to maxDepth.
func CountFiles(root string, maxDepth int) (files int, dirs int) {
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			dirs++
		} else {
			files++
		}
		return nil
	})
	return
}

// FindFiles returns up to limit file paths matching the glob under root.
func FindFiles(root string, maxDepth int, limit int) []string {
	var result []string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > maxDepth {
			return filepath.SkipDir
		}
		result = append(result, path)
		if limit > 0 && len(result) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	return result
}

// WaitForLogPattern waits until the log file (after fromLine) contains the pattern.
func WaitForLogPattern(n *NydusdInstance, fromLine int, pattern string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	lowerPattern := strings.ToLower(pattern)
	for time.Now().Before(deadline) {
		f, err := os.Open(n.LogFile)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum > fromLine {
				if strings.Contains(strings.ToLower(scanner.Text()), lowerPattern) {
					f.Close()
					return true
				}
			}
		}
		f.Close()
		time.Sleep(time.Second)
	}
	return false
}
