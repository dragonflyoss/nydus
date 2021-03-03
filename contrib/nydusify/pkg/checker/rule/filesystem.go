// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"contrib/nydusify/pkg/checker/tool"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"github.com/sirupsen/logrus"
	"lukechampine.com/blake3"
)

// FilesystemRule compares file metadata and data in the two mountpoints:
// Mounted by Nydusd for Nydus image,
// Mounted by Overlayfs for OCI image.
type FilesystemRule struct {
	NydusdConfig    tool.NydusdConfig
	Source          string
	SourceMountPath string
}

// Node records file metadata and file data hash.
type Node struct {
	Path   string
	Size   int64
	Mode   os.FileMode
	Xattrs map[string][]byte
	Hash   []byte
}

func (rule *FilesystemRule) Name() string {
	return "Filesystem"
}

func hashFile(path string) ([]byte, error) {
	hasher := blake3.New(32, nil)

	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "open file before hashing file")
	}
	defer file.Close()

	buf := make([]byte, 2<<15) // 64KB
	for {
		n, err := file.Read(buf)
		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "read file during hashing file")
		}
		if _, err := hasher.Write(buf); err != nil {
			return nil, errors.Wrap(err, "calculate hash of file")
		}
	}

	return hasher.Sum(nil), nil
}

func getXattrs(path string) (map[string][]byte, error) {
	xattrs := make(map[string][]byte)

	names, err := xattr.LList(path)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		data, err := xattr.LGet(path, name)
		if err != nil {
			return nil, err
		}
		xattrs[name] = data
	}

	return xattrs, nil
}

func (rule *FilesystemRule) walk(rootfs string) (map[string]Node, error) {
	nodes := map[string]Node{}

	if err := filepath.Walk(rootfs, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logrus.Warnf("Failed to stat in mountpoint: %s", err)
			return nil
		}

		rootfsPath, err := filepath.Rel(rootfs, path)
		if err != nil {
			return err
		}
		rootfsPath = filepath.Join("/", rootfsPath)

		size := info.Size()
		mode := info.Mode()
		xattrs, err := getXattrs(path)
		if err != nil {
			logrus.Warnf("Failed to get xattr: %s", err)
		}

		// Calculate file data hash if the `backend-type` option be specified,
		// this will cause that nydusd read data from backend, it's network load
		var hash []byte
		if rule.NydusdConfig.BackendType != "" && info.Mode().IsRegular() {
			hash, err = hashFile(path)
			if err != nil {
				return err
			}
		}

		node := Node{
			Path:   rootfsPath,
			Size:   size,
			Mode:   mode,
			Xattrs: xattrs,
			Hash:   hash,
		}
		nodes[rootfsPath] = node

		return nil
	}); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (rule *FilesystemRule) mountSourceImage() (*tool.Image, error) {
	logrus.Infof("Mounting source image to %s", rule.SourceMountPath)

	if err := os.MkdirAll(rule.SourceMountPath, 0755); err != nil {
		return nil, errors.Wrap(err, "create mountpoint directory of source image")
	}

	image := &tool.Image{
		Source: rule.Source,
		Rootfs: rule.SourceMountPath,
	}
	if err := image.Pull(); err != nil {
		return nil, errors.Wrap(err, "pull source image")
	}
	if err := image.Mount(); err != nil {
		return nil, errors.Wrap(err, "mount source image")
	}

	return image, nil
}

func (rule *FilesystemRule) mountNydusImage() (*tool.Nydusd, error) {
	logrus.Infof("Mounting Nydus image to %s", rule.NydusdConfig.MountPath)

	if err := os.MkdirAll(rule.NydusdConfig.BlobCacheDir, 0755); err != nil {
		return nil, errors.Wrap(err, "create blob cache directory for Nydusd")
	}

	if err := os.MkdirAll(rule.NydusdConfig.MountPath, 0755); err != nil {
		return nil, errors.Wrap(err, "create mountpoint directory of Nydus image")
	}

	nydusd, err := tool.NewNydusd(rule.NydusdConfig)
	if err != nil {
		return nil, errors.Wrap(err, "create Nydusd daemon")
	}

	if err := nydusd.Mount(); err != nil {
		return nil, errors.Wrap(err, "mount Nydus image")
	}

	return nydusd, nil
}

func (rule *FilesystemRule) verify() error {
	logrus.Infof("Verifying filesystem for source and Nydus image")

	validate := true
	sourceNodes := map[string]Node{}

	// Concurrently walk the rootfs directory of source and Nydus image
	walkErr := make(chan error)
	go func() {
		var err error
		sourceNodes, err = rule.walk(rule.SourceMountPath)
		walkErr <- err
	}()

	nydusNodes, err := rule.walk(rule.NydusdConfig.MountPath)
	if err != nil {
		return errors.Wrap(err, "walk rootfs of Nydus image")
	}

	if err := <-walkErr; err != nil {
		return errors.Wrap(err, "walk rootfs of source image")
	}

	for path, sourceNode := range sourceNodes {
		nydusNode, exist := nydusNodes[path]
		if !exist {
			logrus.Warnf("File not found in Nydus image: %s", path)
			validate = false
			continue
		}
		delete(nydusNodes, path)

		if path != "/" && !reflect.DeepEqual(sourceNode, nydusNode) {
			logrus.Warnf("File not match in Nydus image: %s", path)
			validate = false
		}
	}

	for path := range nydusNodes {
		logrus.Warnf("File not found in source image: %s", path)
		validate = false
	}

	if !validate {
		return fmt.Errorf("Failed to verify source image and Nydus image")
	}

	return nil
}

func (rule *FilesystemRule) Validate() error {
	// Skip filesystem validation if no source image be specified
	if rule.Source == "" {
		return nil
	}

	image, err := rule.mountSourceImage()
	if err != nil {
		return err
	}
	defer image.Umount()

	nydusd, err := rule.mountNydusImage()
	if err != nil {
		return err
	}
	defer nydusd.Umount()

	if err := rule.verify(); err != nil {
		return err
	}

	return nil
}
