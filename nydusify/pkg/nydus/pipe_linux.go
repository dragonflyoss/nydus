/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"os"

	"golang.org/x/sys/unix"
)

// pipeSize is the capacity requested for the builder's stdin pipe. It is the
// default fs.pipe-max-size, so unprivileged callers get it too.
const pipeSize = 1 << 20

// growPipe enlarges the pipe behind f so the layer tar reaches the builder in
// large hand-offs: with the default 64 KiB the writer and the builder spend
// their time waking each other and contending on the pipe lock. Failure only
// costs throughput, so it is ignored.
func growPipe(f *os.File) {
	raw, err := f.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_, _ = unix.FcntlInt(fd, unix.F_SETPIPE_SZ, pipeSize)
	})
}
