/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package meta

import "path/filepath"

type FileSystemMeta struct {
	RootDir string
}

func (m FileSystemMeta) SnapshotRoot() string {
	return filepath.Join(m.RootDir, "snapshots")
}

func (m FileSystemMeta) CacheRoot() string {
	return filepath.Join(m.RootDir, "cache")
}

func (m FileSystemMeta) SocketRoot() string {
	return filepath.Join(m.RootDir, "socket")
}

func (m FileSystemMeta) ConfigRoot() string {
	return filepath.Join(m.RootDir, "config")
}

func (m FileSystemMeta) LogRoot() string {
	return filepath.Join(m.RootDir, "logs")
}

func (m FileSystemMeta) UpperPath(id string) string {
	return filepath.Join(m.RootDir, "snapshots", id, "fs")
}
