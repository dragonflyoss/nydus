/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"os/exec"
	"syscall"
)

// DieWithParent has the kernel send SIGTERM to the process cmd starts once
// this process is gone, however it went, so that no nydus child outlives it:
// a FUSE daemon would keep its mount, with nothing left to clean it up. Call
// it before the command is started.
//
// The kernel sends the signal when the thread that started the child ends.
// The Go runtime only ends a thread whose goroutine exits while locked to it,
// which nothing here does.
func DieWithParent(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
}
