// Package proc samples the resources a daemon holds, for leak checks.
package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Sample is a point-in-time view of a process.
type Sample struct {
	FDs     int
	Threads int
	// RSS is the resident set size in bytes.
	RSS int64
}

// Of samples the process pid.
func Of(pid int) (Sample, error) {
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return Sample{}, err
	}

	status, err := Status(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return Sample{}, err
	}

	threads, _ := strconv.Atoi(status["Threads"])
	rssKB, _ := strconv.ParseInt(strings.TrimSuffix(status["VmRSS"], " kB"), 10, 64)

	return Sample{FDs: len(fds), Threads: threads, RSS: rssKB << 10}, nil
}

// Status parses a /proc status file of "Key:\tvalue" lines into a map.
func Status(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()
	out := map[string]string{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}

	return out, sc.Err()
}

// Children returns the pids whose parent is pid.
func Children(pid int) []int {
	var out []int

	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, path := range stats {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// The command name is parenthesised and may hold spaces.
		i := strings.LastIndexByte(string(data), ')')
		if i < 0 {
			continue
		}

		fields := strings.Fields(string(data[i+1:]))
		if len(fields) < 2 {
			continue
		}

		if ppid, _ := strconv.Atoi(fields[1]); ppid == pid {
			child, _ := strconv.Atoi(filepath.Base(filepath.Dir(path)))
			out = append(out, child)
		}
	}

	return out
}

// running reports whether pid exists and is not a zombie.
func running(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}

	i := strings.LastIndexByte(string(data), ')')
	fields := strings.Fields(string(data[i+1:]))

	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// ExpectGone fails t unless every pid has exited (or is a zombie awaiting
// its new parent) within timeout.
func ExpectGone(t testing.TB, pids []int, timeout time.Duration) {
	t.Helper()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	deadline := time.Now().Add(timeout)

	for {
		var alive []int

		for _, pid := range pids {
			if running(pid) {
				alive = append(alive, pid)
			}
		}

		if len(alive) == 0 {
			return
		}

		if time.Now().After(deadline) {
			t.Errorf("processes left behind: %v", alive)
			return
		}

		<-tick.C
	}
}
