/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkBlobMetaAcrossFilesystems(t *testing.T) {
	sourceDir, err := os.MkdirTemp("/dev/shm", "nydus-blob-meta-")
	require.NoError(t, err, "cross-filesystem coverage requires writable /dev/shm")
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(sourceDir)) })
	src := filepath.Join(sourceDir, "blob.blob.meta")
	data := bytes.Repeat([]byte("cross-filesystem metadata"), 4096)
	require.NoError(t, os.WriteFile(src, data, 0o600))
	cache := t.TempDir()
	probe := filepath.Join(cache, "hardlink-probe")
	require.ErrorIs(t, os.Link(src, probe), syscall.EXDEV, "TMPDIR and /dev/shm must be different filesystems")

	require.NoError(t, LinkBlobMetaFiles(context.Background(), slices.Repeat([]string{src}, 32), cache))
	require.NoError(t, os.Remove(src))
	got, err := os.ReadFile(filepath.Join(cache, "blob.blob.meta"))
	require.NoError(t, err)
	require.Equal(t, data, got)
	entries, err := os.ReadDir(cache)
	require.NoError(t, err)
	require.Len(t, entries, 1, "successful concurrent copies must not leave temporary files")
}
