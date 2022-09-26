// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func run(cmd string, args ...string) error {
	_cmd := exec.Command("sh", "-c", cmd)
	_cmd.Stdout = os.Stdout
	_cmd.Stderr = os.Stderr
	return _cmd.Run()
}

type Image struct {
	Layers     []ocispec.Descriptor
	Source     string
	SourcePath string
	Rootfs     string
}

// Mount mounts rootfs of OCI image.
func (image *Image) Mount() error {
	image.Umount()

	var dirs []string
	layerLen := len(image.Layers)
	for i := range image.Layers {
		layerDir := filepath.Join(image.SourcePath, image.Layers[layerLen-i-1].Digest.Encoded())
		dirs = append(dirs, strings.ReplaceAll(layerDir, ":", "\\:"))
	}

	lowerOption := strings.Join(dirs, ":")
	// Handle long options string overed 4096 chars, split them to
	// two overlay mounts.
	if len(lowerOption) >= 4096 {
		half := (len(dirs) - 1) / 2
		upperDirs := dirs[half+1:]
		lowerDirs := dirs[:half+1]
		lowerOverlay := image.Rootfs + "_lower"
		if err := os.MkdirAll(lowerOverlay, 0755); err != nil {
			return err
		}
		if err := run(fmt.Sprintf(
			"mount -t overlay overlay -o lowerdir='%s' %s",
			strings.Join(upperDirs, ":"), lowerOverlay,
		)); err != nil {
			return err
		}
		lowerDirs = append(lowerDirs, lowerOverlay)
		lowerOption = strings.Join(lowerDirs, ":")
	}

	if err := run(fmt.Sprintf(
		"mount -t overlay overlay -o lowerdir='%s' %s",
		lowerOption, image.Rootfs,
	)); err != nil {
		return err
	}

	return nil
}

// Umount umounts rootfs mountpoint of OCI image.
func (image *Image) Umount() error {
	lowerOverlay := image.Rootfs + "_lower"
	if _, err := os.Stat(lowerOverlay); err == nil {
		if err := run(fmt.Sprintf("umount %s", lowerOverlay)); err != nil {
			return err
		}
	}

	if _, err := os.Stat(image.Rootfs); err == nil {
		if err := run(fmt.Sprintf("umount %s", image.Rootfs)); err != nil {
			return err
		}
	}

	if err := os.RemoveAll(image.SourcePath); err != nil {
		return err
	}

	return nil
}
