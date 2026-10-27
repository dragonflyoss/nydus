/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mounter

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"golang.org/x/sys/unix"
)

// TestMountChild exercises only the process boundary; FUSE readiness and
// unmounting are covered by TestMount/lifecycle in the end-to-end suite.
func TestMountChild(t *testing.T) {
	mode := os.Getenv("NYDUS_MOUNT_CHILD")
	if mode == "" {
		return
	}
	dir := os.Getenv("NYDUS_MOUNT_CONTROL")
	signals := make(chan os.Signal, 1)
	if mode == "unresponsive" {
		signal.Ignore(unix.SIGTERM)
	} else {
		signal.Notify(signals, unix.SIGTERM)
	}
	if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "before_ready" {
		os.Exit(23)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			os.Exit(23)
		}
		select {
		case <-signals:
			if mode == "cancel_exit_race" {
				os.Exit(23)
			}
			os.Exit(0)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestMountNydusLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, wantError string
		cancel          bool
	}{
		{name: "startup_failure", wantError: "start nydus fuse"},
		{name: "before_ready", wantError: "nydus fuse exited: exit status 23"},
		{name: "running_failure", wantError: "nydus fuse exited: exit status 23"},
		{name: "cancel", cancel: true},
		{name: "cancel_exit_race", cancel: true},
		{name: "unresponsive", cancel: true, wantError: "nydus fuse exited: signal: killed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			mountpoint := filepath.Join(work, "mnt")
			if err := os.Mkdir(mountpoint, 0o700); err != nil {
				t.Fatal(err)
			}
			provider, err := remote.NewProvider(remote.Option{WorkDir: filepath.Join(work, "content"), TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bootstrap, err := oci.WriteBootstrapLayer(ctx, provider.ContentStore(), []byte("process-boundary bootstrap"), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			img := &nydusfs.Image{Ref: "localhost:5000/mount:test", Bootstrap: bootstrap}
			builder := filepath.Join(work, "builder")
			if tc.name != "startup_failure" {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				script := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestMountChild$ -- \"$@\"\n", executable)
				if err := os.WriteFile(builder, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("NYDUS_MOUNT_CHILD", tc.name)
			t.Setenv("NYDUS_MOUNT_CONTROL", work)
			m := &Mounter{opt: MountOption{BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint}}
			done := make(chan error, 1)
			go func() {
				done <- m.mountNydus(ctx, provider, provider.ContentStore(), img, filepath.Join(work, "scratch"))
				close(done)
			}()
			var pid int
			t.Cleanup(func() {
				cancel()
				if pid != 0 {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
				<-done
			})
			if tc.name != "startup_failure" {
				deadline := time.Now().Add(5 * time.Second)
				for pid == 0 && time.Now().Before(deadline) {
					data, _ := os.ReadFile(filepath.Join(work, "pid"))
					pid, _ = strconv.Atoi(string(data))
					time.Sleep(10 * time.Millisecond)
				}
				if pid == 0 {
					t.Fatal("mount child never started")
				}
				if tc.name != "before_ready" {
					for {
						if _, err := os.Stat(filepath.Join(work, "ready")); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("child never became ready for termination")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
			if tc.cancel {
				cancel()
			}
			if tc.name == "running_failure" || tc.name == "cancel_exit_race" {
				if err := os.WriteFile(filepath.Join(work, "release"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if tc.wantError == "" && err != nil {
					t.Fatalf("cancelled mount: %v", err)
				}
				if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("mount did not exit within 8s")
			}
			if pid != 0 {
				if err := unix.Kill(pid, 0); err != unix.ESRCH {
					t.Errorf("child %d not reaped: %v", pid, err)
				}
			}
			entries, err := os.ReadDir(mountpoint)
			if err != nil || len(entries) != 0 {
				t.Fatalf("mountpoint changed on process failure: %v, %v", entries, err)
			}
		})
	}
}
