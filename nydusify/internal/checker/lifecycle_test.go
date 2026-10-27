/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

func mountRule(t *testing.T, builder string) (filesystemRule, *nydusfs.Image) {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	boot, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("bootstrap"), nil, nil)
	require.NoError(t, err)
	img := &nydusfs.Image{Ref: "registry.invalid/source:tag", Kind: nydusfs.KindNydus, Bootstrap: boot}
	return filesystemRule{cs: provider.ContentStore(), provider: provider, builder: builder, workDir: t.TempDir()}, img
}

func TestMountFailureCleansScratch(t *testing.T) {
	for _, kind := range []string{"cannot start", "exits before ready"} {
		t.Run(kind, func(t *testing.T) {
			builder := filepath.Join(t.TempDir(), "nydus")
			if kind == "exits before ready" {
				require.NoError(t, os.WriteFile(builder, []byte("#!/bin/sh\necho 'injected startup failure' >&2\nexit 23\n"), 0o700))
			}
			rule, img := mountRule(t, builder)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			root, cleanup, err := rule.mount(ctx, "source", remote.Source, img)
			require.Error(t, err)
			require.Empty(t, root)
			require.Nil(t, cleanup)
			require.NoError(t, ctx.Err(), "an exited child must fail immediately, not wait for readiness timeout")
			if kind == "exits before ready" {
				require.ErrorContains(t, err, "injected startup failure")
			} else {
				require.ErrorContains(t, err, "start nydus fuse")
			}
			entries, err := os.ReadDir(rule.workDir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestMountCancellationReapsChild(t *testing.T) {
	dir := t.TempDir()
	builder := filepath.Join(dir, "nydus")
	pidFile := filepath.Join(dir, "pid")
	script := "#!/bin/sh\necho $$ > " + strconv.Quote(pidFile) + "\nexec sleep 30\n"
	require.NoError(t, os.WriteFile(builder, []byte(script), 0o700))
	rule, img := mountRule(t, builder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := rule.mount(ctx, "source", remote.Source, img)
		done <- err
	}()
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(pidFile)
		return err == nil && strings.TrimSpace(string(data)) != ""
	}, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("canceled mount did not reap the child")
	}
	data, err := os.ReadFile(pidFile)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH)
	entries, err := os.ReadDir(rule.workDir)
	require.NoError(t, err)
	require.Empty(t, entries)
}
