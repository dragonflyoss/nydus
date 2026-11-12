/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockProcessGone reports whether the process pid has exited, reaped or not.
func mockProcessGone(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}

	// The state follows the command name, which is the only field in brackets.
	state := bytes.TrimSpace(stat[bytes.LastIndexByte(stat, ')')+1:])
	return bytes.HasPrefix(state, []byte("Z"))
}

// TestDieWithParentChild is the parent of the cases of TestDieWithParent: it
// starts a child, reports its pid and waits to be killed.
func TestDieWithParentChild(t *testing.T) {
	mode := os.Getenv("NYDUS_DIE_WITH_PARENT")
	if mode == "" {
		return
	}

	cmd := exec.Command("sleep", "300")
	if mode == "bound" {
		DieWithParent(cmd)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	fmt.Println(cmd.Process.Pid)
	time.Sleep(5 * time.Minute)
}

func TestDieWithParent(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		expect func(t *testing.T, child int)
	}{
		{
			name: "bound child ends with its parent",
			mode: "bound",
			expect: func(t *testing.T, child int) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return mockProcessGone(child) }, 10*time.Second, 10*time.Millisecond)
			},
		},
		{
			name: "unbound child outlives its parent",
			mode: "unbound",
			expect: func(t *testing.T, child int) {
				assert := assert.New(t)
				assert.Never(func() bool { return mockProcessGone(child) }, 300*time.Millisecond, 10*time.Millisecond)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := exec.Command(os.Args[0], "-test.run=^TestDieWithParentChild$")
			parent.Env = append(os.Environ(), "NYDUS_DIE_WITH_PARENT="+tc.mode)
			stdout, err := parent.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}

			if err := parent.Start(); err != nil {
				t.Fatal(err)
			}

			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}

			child, err := strconv.Atoi(strings.TrimSpace(line))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })

			if err := parent.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = parent.Wait()

			tc.expect(t, child)
		})
	}
}
