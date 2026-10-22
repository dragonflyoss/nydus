// Package proc samples the resources a daemon holds, for leak checks.
package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	status, err := readStatus(pid)
	if err != nil {
		return Sample{}, err
	}
	threads, _ := strconv.Atoi(status["Threads"])
	rssKB, _ := strconv.ParseInt(strings.TrimSuffix(status["VmRSS"], " kB"), 10, 64)
	return Sample{FDs: len(fds), Threads: threads, RSS: rssKB << 10}, nil
}

func readStatus(pid int) (map[string]string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
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

// MountsUnder lists the mountpoints at or below dir.
func MountsUnder(dir string) ([]string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mnt := unescape(fields[4])
		if mnt == dir || strings.HasPrefix(mnt, dir+"/") {
			out = append(out, mnt)
		}
	}
	return out, sc.Err()
}

// unescape decodes the octal escapes mountinfo uses for space, tab,
// newline and backslash.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
