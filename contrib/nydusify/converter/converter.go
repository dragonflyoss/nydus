// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/nydus"
	"contrib/nydusify/remote"
)

type Option struct {
	ContainerdSock string
	Source         string
	Target         string
	SourceAuth     string
	TargetAuth     string
	SourceInsecure bool
	TargetInsecure bool

	WorkDir          string
	PrefetchDir      string
	SignatureKeyPath string
	NydusImagePath   string
}

func prepareWorkDir(option Option) (string, error) {
	// Make directory for source image
	sourceDir := filepath.Join(option.WorkDir, option.Source)
	if err := os.RemoveAll(sourceDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(sourceDir, 0666); err != nil {
		return "", err
	}

	// Make directory for targe image
	targetDir := filepath.Join(option.WorkDir, option.Target)

	if err := os.RemoveAll(targetDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(targetDir, 0666); err != nil {
		return "", err
	}

	blobsDir := filepath.Join(targetDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0666); err != nil {
		return "", err
	}

	return targetDir, nil
}

// Convert source image to target image
func Convert(option Option) error {
	targetDir, err := prepareWorkDir(option)
	if err != nil {
		return errors.Wrap(err, "prepare work directory")
	}

	remote, err := remote.New(remote.Option{
		ContainerdSock: option.ContainerdSock,
		Source:         option.Source,
		Target:         option.Target,
		SourceAuth:     option.SourceAuth,
		TargetAuth:     option.TargetAuth,
		SourceInsecure: option.SourceInsecure,
		TargetInsecure: option.TargetInsecure,
	})
	if err != nil {
		return errors.Wrap(err, "connect to containerd service")
	}
	defer remote.Clean()

	// Pull source image
	if err := remote.Pull(); err != nil {
		return errors.Wrap(err, "pull source image")
	}

	parentBootstrapPath := ""
	bootstrapPath := filepath.Join(targetDir, "bootstrap")
	blobsDir := filepath.Join(targetDir, "blobs")

	backendConfig := fmt.Sprintf(`{"dir": "%s"}`, blobsDir)
	builder := nydus.NewBuilder(option.NydusImagePath)

	pushTask := sync.WaitGroup{}

	// Unpack source image layer then build to nydus bootstrap and blob
	if err = remote.Unpack(option.WorkDir, func(layerDir string) error {
		layerID := filepath.Base(layerDir)

		logrus.Infof("Building layer %s", layerID)

		if parentBootstrapPath != "" {
			if err := os.Rename(bootstrapPath, parentBootstrapPath); err != nil {
				return err
			}
		}

		// Build nydus bootstrap and blob
		// TODO: skip to build if the layer has been built
		if err = builder.Run(nydus.Option{
			ParentBootstrapPath: parentBootstrapPath,
			BootstrapPath:       bootstrapPath,
			RootfsPath:          layerDir,
			BackendType:         "localfs",
			BackendConfig:       backendConfig,
			PrefetchDir:         option.PrefetchDir,
		}); err != nil {
			return errors.Wrap(err, fmt.Sprintf("build layer %s", layerID))
		}

		if parentBootstrapPath == "" {
			parentBootstrapPath = filepath.Join(targetDir, "bootstrap-parent")
		}

		// Push nydus blob layer
		blobs, err := ioutil.ReadDir(blobsDir)
		if err != nil {
			return err
		}

		sort.Slice(blobs, func(i, j int) bool {
			return blobs[i].ModTime().UnixNano() < blobs[j].ModTime().UnixNano()
		})

		if len(blobs) > 0 {
			pushTask.Add(1)
			go func() {
				defer pushTask.Done()

				blobID := blobs[len(blobs)-1].Name()
				blobPath := filepath.Join(blobsDir, blobID)

				if err := remote.PushBlobLayer(blobPath); err != nil {
					logrus.Fatalf("Failed to push blob layer %s: %s", blobID, err)
				}
			}()
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "unpack source image layer")
	}

	pushTask.Wait()

	// Push nydus bootstrap layer
	if err := remote.PushBoostrapLayer(bootstrapPath, option.SignatureKeyPath); err != nil {
		return errors.Wrap(err, "push bootstrap layer")
	}

	// Push new image config
	if err := remote.PushConfig(); err != nil {
		return errors.Wrap(err, "push target image config")
	}

	// Push nydus manifest
	if err := remote.PushManifest(); err != nil {
		return errors.Wrap(err, "push target image manifest")
	}

	// Push manifest index included source manifest and nydus manifest
	if err := remote.PushManifestIndex(); err != nil {
		return errors.Wrap(err, "push target image manifest index")
	}

	logrus.Infof("Success convert image %s to %s", option.Source, option.Target)

	return nil
}
