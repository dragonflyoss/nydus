// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
)

func mkMounts(dirs []string) []mount.Mount {
	var options []string

	if len(dirs) == 0 {
		return nil
	}

	if len(dirs) == 1 {
		return []mount.Mount{
			{
				Source: dirs[0],
				Type:   "bind",
				Options: []string{
					"ro",
					"rbind",
				},
			},
		}
	}

	options = append(options, fmt.Sprintf("lowerdir=%s", strings.Join(dirs, ":")))
	return []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}
}

func CheckImageType(parsed *parser.Parsed) string {
	if parsed.NydusImage != nil {
		return "nydus"
	} else if parsed.OCIImage != nil {
		return "oci"
	}
	return "unknown"
}

type Image struct {
	Layers       []ocispec.Descriptor
	LayerBaseDir string
	Rootfs       string
}

// Mount mounts rootfs of OCI image.
func (image *Image) Mount() error {
	if err := os.MkdirAll(image.Rootfs, 0750); err != nil {
		return errors.Wrap(err, "create rootfs dir")
	}

	var dirs []string
	count := len(image.Layers)
	for idx := range image.Layers {
		layerName := fmt.Sprintf("layer-%d", count-idx-1)
		layerDir := filepath.Join(image.LayerBaseDir, layerName)
		dirs = append(dirs, strings.ReplaceAll(layerDir, ":", "\\:"))
	}

	mounts := mkMounts(dirs)
	if err := mount.All(mounts, image.Rootfs); err != nil {
		return errors.Wrap(err, "mount source layer")
	}

	return nil
}

// Umount umounts rootfs mountpoint of OCI image.
func (image *Image) Umount() error {
	if _, err := os.Stat(image.Rootfs); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.Wrap(err, "stat rootfs")
	}

	if err := mount.Unmount(image.Rootfs, 0); err != nil {
		return errors.Wrap(err, "umount rootfs")
	}

	if err := os.RemoveAll(image.Rootfs); err != nil {
		return errors.Wrap(err, "remove rootfs")
	}

	return nil
}
