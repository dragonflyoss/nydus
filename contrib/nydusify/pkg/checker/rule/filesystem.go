// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/distribution/reference"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"
	"github.com/pkg/xattr"
	"github.com/sirupsen/logrus"
)

// WorkerCount specifies source layer pull concurrency
var WorkerCount uint = 8

// FilesystemRule compares file metadata and data in the two mountpoints:
// Mounted by nydusd for nydus image,
// Mounted by Overlayfs for OCI image.
type FilesystemRule struct {
	WorkDir    string
	NydusdPath string

	SourceImage         *Image
	TargetImage         *Image
	SourceBackendType   string
	SourceBackendConfig string
	TargetBackendType   string
	TargetBackendConfig string
}

type Image struct {
	Parsed   *parser.Parsed
	Insecure bool
}

// Node records file metadata and file data hash.
type Node struct {
	Path    string
	Size    int64
	Mode    os.FileMode
	Rdev    uint64
	Symlink string
	UID     uint32
	GID     uint32
	Xattrs  map[string][]byte
	Hash    []byte
}

type RegistryBackendConfig struct {
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Repo       string `json:"repo"`
	Auth       string `json:"auth,omitempty"`
	SkipVerify bool   `json:"skip_verify,omitempty"`
}

func (node *Node) String() string {
	return fmt.Sprintf(
		"path: %s, size: %d, mode: %d, rdev: %d, symink: %s, uid: %d, gid: %d, "+
			"xattrs: %v, hash: %s", node.Path, node.Size, node.Mode, node.Rdev, node.Symlink,
		node.UID, node.GID, node.Xattrs, hex.EncodeToString(node.Hash),
	)
}

func (rule *FilesystemRule) Name() string {
	return "filesystem"
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
			return errors.Wrapf(err, "Failed to stat file %s", path)
		}

		rootfsPath, err := filepath.Rel(rootfs, path)
		if err != nil {
			return err
		}
		rootfsPath = filepath.Join("/", rootfsPath)

		var size int64
		if !info.IsDir() {
			// Ignore directory size check
			size = info.Size()
		}

		mode := info.Mode()
		var symlink string
		if mode&os.ModeSymlink == os.ModeSymlink {
			if symlink, err = os.Readlink(path); err != nil {
				return errors.Wrapf(err, "read link %s", path)
			}
		} else {
			symlink = rootfsPath
		}

		var stat syscall.Stat_t
		if err := syscall.Lstat(path, &stat); err != nil {
			return errors.Wrapf(err, "lstat %s", path)
		}

		xattrs, err := getXattrs(path)
		if err != nil {
			logrus.Warnf("failed to get xattr: %s", err)
		}

		// Calculate file data hash if the `backend-type` option be specified,
		// this will cause that nydusd read data from backend, it's network load
		var hash []byte
		if info.Mode().IsRegular() {
			hash, err = utils.HashFile(path)
			if err != nil {
				return err
			}
		}

		node := Node{
			Path:    rootfsPath,
			Size:    size,
			Mode:    mode,
			Rdev:    stat.Rdev,
			Symlink: symlink,
			UID:     stat.Uid,
			GID:     stat.Gid,
			Xattrs:  xattrs,
			Hash:    hash,
		}
		nodes[rootfsPath] = node

		return nil
	}); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (rule *FilesystemRule) mountNydusImage(image *Image, dir string) (func() error, error) {
	logrus.WithField("type", tool.CheckImageType(image.Parsed)).WithField("image", image.Parsed.Remote.Ref).Info("mounting image")

	digestValidate := false
	if image.Parsed.NydusImage != nil {
		nydusManifest := parser.FindNydusBootstrapDesc(&image.Parsed.NydusImage.Manifest)
		if nydusManifest != nil {
			v := utils.GetNydusFsVersionOrDefault(nydusManifest.Annotations, utils.V5)
			if v == utils.V5 {
				// Digest validate is not currently supported for v6,
				// but v5 supports it. In order to make the check more sufficient,
				// this validate needs to be turned on for v5.
				digestValidate = true
			}
		}
	}

	backendType := rule.SourceBackendType
	backendConfig := rule.SourceBackendConfig
	if dir == "target" {
		backendType = rule.TargetBackendType
		backendConfig = rule.TargetBackendConfig
	}

	mountDir := filepath.Join(rule.WorkDir, dir, "mnt")
	nydusdDir := filepath.Join(rule.WorkDir, dir, "nydusd")
	if err := os.MkdirAll(nydusdDir, 0755); err != nil {
		return nil, errors.Wrap(err, "create nydusd directory")
	}

	nydusdConfig := tool.NydusdConfig{
		EnablePrefetch: true,
		NydusdPath:     rule.NydusdPath,
		BackendType:    backendType,
		BackendConfig:  backendConfig,
		BootstrapPath:  filepath.Join(rule.WorkDir, dir, "nydus_bootstrap/image/image.boot"),
		ConfigPath:     filepath.Join(nydusdDir, "config.json"),
		BlobCacheDir:   filepath.Join(nydusdDir, "cache"),
		APISockPath:    filepath.Join(nydusdDir, "api.sock"),
		MountPath:      mountDir,
		Mode:           "direct",
		DigestValidate: digestValidate,
	}

	if err := os.MkdirAll(nydusdConfig.BlobCacheDir, 0755); err != nil {
		return nil, errors.Wrap(err, "create blob cache directory for nydusd")
	}

	if err := os.MkdirAll(nydusdConfig.MountPath, 0755); err != nil {
		return nil, errors.Wrap(err, "create mountpoint directory of nydus image")
	}

	ref, err := reference.ParseNormalizedNamed(image.Parsed.Remote.Ref)
	if err != nil {
		return nil, err
	}

	if nydusdConfig.BackendType == "" {
		nydusdConfig.BackendType = "registry"

		if nydusdConfig.BackendConfig == "" {
			backendConfig, err := utils.NewRegistryBackendConfig(ref, image.Insecure)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse backend configuration")
			}

			if image.Insecure {
				backendConfig.SkipVerify = true
			}

			if image.Parsed.Remote.IsWithHTTP() {
				backendConfig.Scheme = "http"
			}

			bytes, err := json.Marshal(backendConfig)
			if err != nil {
				return nil, errors.Wrap(err, "parse registry backend config")
			}
			nydusdConfig.BackendConfig = string(bytes)
		}
	}

	nydusd, err := tool.NewNydusd(nydusdConfig)
	if err != nil {
		return nil, errors.Wrap(err, "create nydusd daemon")
	}

	if err := nydusd.Mount(); err != nil {
		return nil, errors.Wrap(err, "mount nydus image")
	}

	umount := func() error {
		if err := nydusd.Umount(false); err != nil {
			return errors.Wrap(err, "umount nydus image")
		}
		if err := os.RemoveAll(mountDir); err != nil {
			logrus.WithError(err).Warnf("cleanup mount directory: %s", mountDir)
		}
		if err := os.RemoveAll(nydusdDir); err != nil {
			logrus.WithError(err).Warnf("cleanup nydusd directory: %s", nydusdDir)
		}
		return nil
	}

	return umount, nil
}

func (rule *FilesystemRule) mountOCIImage(image *Image, dir string) (func() error, error) {
	logrus.WithField("type", tool.CheckImageType(image.Parsed)).WithField("image", image.Parsed.Remote.Ref).Infof("mounting image")

	mountPath := filepath.Join(rule.WorkDir, dir, "mnt")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		return nil, errors.Wrap(err, "create mountpoint directory")
	}
	layerBasePath := filepath.Join(rule.WorkDir, dir, "layers")
	if err := os.MkdirAll(layerBasePath, 0755); err != nil {
		return nil, errors.Wrap(err, "create layer base directory")
	}

	layers := image.Parsed.OCIImage.Manifest.Layers
	worker := utils.NewWorkerPool(WorkerCount, uint(len(layers)))

	for idx := range layers {
		worker.Put(func(idx int) func() error {
			return func() error {
				layer := layers[idx]
				reader, err := image.Parsed.Remote.Pull(context.Background(), layer, true)
				if err != nil {
					return errors.Wrap(err, "pull source image layers from the remote registry")
				}

				layerDir := filepath.Join(layerBasePath, fmt.Sprintf("layer-%d", idx))
				if err = utils.UnpackTargz(context.Background(), layerDir, reader, true); err != nil {
					return errors.Wrap(err, "unpack source image layers")
				}

				return nil
			}
		}(idx))
	}

	if err := <-worker.Waiter(); err != nil {
		return nil, errors.Wrap(err, "pull source image layers in wait")
	}

	mounter := &tool.Image{
		Layers:       layers,
		LayerBaseDir: layerBasePath,
		Rootfs:       mountPath,
	}

	if err := mounter.Umount(); err != nil {
		return nil, errors.Wrap(err, "umount previous rootfs")
	}

	if err := mounter.Mount(); err != nil {
		return nil, errors.Wrap(err, "mount source image")
	}

	umount := func() error {
		if err := mounter.Umount(); err != nil {
			logrus.WithError(err).Warnf("umount rootfs")
		}
		if err := os.RemoveAll(layerBasePath); err != nil {
			logrus.WithError(err).Warnf("cleanup layers directory %s", layerBasePath)
		}
		return nil
	}

	return umount, nil
}

func (rule *FilesystemRule) mountImage(image *Image, dir string) (func() error, error) {
	if image.Parsed.OCIImage != nil {
		return rule.mountOCIImage(image, dir)
	} else if image.Parsed.NydusImage != nil {
		return rule.mountNydusImage(image, dir)
	}

	return nil, fmt.Errorf("invalid image for mounting")
}

func (rule *FilesystemRule) verify(sourceRootfs, targetRootfs string) error {
	logrus.Infof("comparing filesystem")

	sourceNodes := map[string]Node{}

	// Concurrently walk the rootfs directory of source and nydus image
	walkErr := make(chan error)
	go func() {
		var err error
		sourceNodes, err = rule.walk(sourceRootfs)
		walkErr <- err
	}()

	targetNodes, err := rule.walk(targetRootfs)
	if err != nil {
		return errors.Wrap(err, "walk rootfs of source image")
	}

	if err := <-walkErr; err != nil {
		return errors.Wrap(err, "walk rootfs of source image")
	}

	for path, sourceNode := range sourceNodes {
		targetNode, exist := targetNodes[path]
		if !exist {
			return fmt.Errorf("file not found in target image: %s", path)
		}
		delete(targetNodes, path)

		if path != "/" && !reflect.DeepEqual(sourceNode, targetNode) {
			return fmt.Errorf("file not match in target image:\n\t[source] %s\n\t[target] %s", sourceNode.String(), targetNode.String())
		}
	}

	for path := range targetNodes {
		return fmt.Errorf("file not found in source image: %s", path)
	}

	return nil
}

func (rule *FilesystemRule) Validate() error {
	// Skip filesystem validation if no source or target image be specified
	if rule.SourceImage.Parsed == nil || rule.TargetImage.Parsed == nil {
		return nil
	}

	umountSource, err := rule.mountImage(rule.SourceImage, "source")
	if err != nil {
		return err
	}
	defer umountSource()

	umountTarget, err := rule.mountImage(rule.TargetImage, "target")
	if err != nil {
		return err
	}
	defer umountTarget()

	return rule.verify(
		filepath.Join(rule.WorkDir, "source/mnt"),
		filepath.Join(rule.WorkDir, "target/mnt"),
	)
}
