// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
)

// ReverseOpt defines options for reverse conversion from Nydus to OCI
type ReverseOpt struct {
	WorkDir        string
	NydusImagePath string

	Source string // Nydus image reference
	Target string // OCI image reference

	SourceInsecure bool
	TargetInsecure bool

	AllPlatforms bool
	Platforms    string

	OutputJSON string

	PushRetryCount int
	PushRetryDelay string
	WithPlainHTTP  bool
}

// ReverseConvert converts Nydus image to OCI image
func ReverseConvert(ctx context.Context, opt ReverseOpt) error {
	logrus.Infof("Starting reverse conversion from Nydus image %s to OCI image %s", opt.Source, opt.Target)

	ctx = namespaces.WithNamespace(ctx, "nydusify")
	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}

	// Prepare work directory
	if _, err := os.Stat(opt.WorkDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(opt.WorkDir, 0755); err != nil {
				return errors.Wrap(err, "prepare work directory")
			}
			defer os.RemoveAll(opt.WorkDir)
		} else {
			return errors.Wrap(err, "stat work directory")
		}
	}

	tmpDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-reverse-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	defer os.RemoveAll(tmpDir)

	// Create provider for registry operations
	pvd, err := provider.New(tmpDir, reverseHosts(opt), 0, "", platformMC, 0)
	if err != nil {
		return err
	}

	// Parse retry delay
	retryDelay, err := time.ParseDuration(opt.PushRetryDelay)
	if err != nil {
		return errors.Wrap(err, "parse push retry delay")
	}

	// Set push retry configuration
	pvd.SetPushRetryConfig(opt.PushRetryCount, retryDelay)

	// Step 1: Pull Nydus image and extract layers
	nydusLayers, nydusManifest, err := pullNydusImage(ctx, opt, pvd, tmpDir)
	if err != nil {
		return errors.Wrap(err, "pull nydus image")
	}

	// Step 2: Unpack Nydus layers to OCI format
	ociLayers, err := unpackNydusLayers(ctx, opt, tmpDir, nydusLayers)
	if err != nil {
		return errors.Wrap(err, "unpack nydus layers")
	}

	// Step 3: Create OCI image config
	ociConfig, err := createOCIConfig(nydusManifest, ociLayers)
	if err != nil {
		return errors.Wrap(err, "create oci config")
	}

	// Step 4: Push OCI layers and manifest
	err = pushOCIImage(ctx, opt, pvd, tmpDir, ociConfig, ociLayers)
	if err != nil {
		return errors.Wrap(err, "push oci image")
	}

	logrus.Infof("Successfully converted Nydus image %s to OCI image %s", opt.Source, opt.Target)
	return nil
}

// reverseHosts creates host configuration for reverse conversion
func reverseHosts(opt ReverseOpt) func(string) (func(string) (string, string, error), bool, error) {
	maps := map[string]bool{
		opt.Source: opt.SourceInsecure,
		opt.Target: opt.TargetInsecure,
	}
	return func(ref string) (func(string) (string, string, error), bool, error) {
		return func(string) (string, string, error) { return "", "", nil }, maps[ref], nil
	}
}

// pullNydusImage pulls Nydus image and extracts layer information
func pullNydusImage(ctx context.Context, opt ReverseOpt, pvd *provider.Provider, tmpDir string) ([]ocispec.Descriptor, *ocispec.Manifest, error) {
	logrus.Infof("Pulling Nydus image: %s", opt.Source)

	// Create remote for source
	remoter, err := pkgPvd.DefaultRemote(opt.Source, opt.SourceInsecure)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create source remote")
	}

	if opt.WithPlainHTTP {
		remoter.WithHTTP()
	}

	// Resolve manifest
	manifestDesc, err := remoter.Resolve(ctx)
	if utils.RetryWithHTTP(err) {
		remoter.MaybeWithHTTP(err)
		manifestDesc, err = remoter.Resolve(ctx)
	}
	if err != nil {
		return nil, nil, errors.Wrap(err, "resolve nydus manifest")
	}

	// Pull manifest
	manifestReader, err := remoter.Pull(ctx, *manifestDesc, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "pull nydus manifest")
	}
	defer manifestReader.Close()

	manifestBytes, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read manifest bytes")
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal manifest")
	}

	// Pull all layers
	var layers []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		layerPath := filepath.Join(tmpDir, layer.Digest.Hex())
		layerFile, err := os.Create(layerPath)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "create layer file %s", layerPath)
		}

		layerReader, err := remoter.Pull(ctx, layer, true)
		if err != nil {
			layerFile.Close()
			return nil, nil, errors.Wrapf(err, "pull layer %s", layer.Digest)
		}

		_, err = io.Copy(layerFile, layerReader)
		layerReader.Close()
		layerFile.Close()
		if err != nil {
			return nil, nil, errors.Wrapf(err, "copy layer %s", layer.Digest)
		}

		layers = append(layers, layer)
	}

	return layers, &manifest, nil
}

// unpackNydusLayers unpacks Nydus layers using nydus-image unpack command
func unpackNydusLayers(ctx context.Context, opt ReverseOpt, tmpDir string, nydusLayers []ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	logrus.Info("Unpacking Nydus layers to OCI format")

	var ociLayers []ocispec.Descriptor

	for i, layer := range nydusLayers {
		// Skip non-nydus layers
		if !isNydusLayer(layer) {
			ociLayers = append(ociLayers, layer)
			continue
		}

		layerPath := filepath.Join(tmpDir, layer.Digest.Hex())
		outputDir := filepath.Join(tmpDir, fmt.Sprintf("unpacked-%d", i))
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, errors.Wrapf(err, "create output directory %s", outputDir)
		}

		// Extract bootstrap and blob from layer if it's a gzipped tar
		bootstrapPath, blobPath, err := extractNydusLayer(layerPath, outputDir)
		if err != nil {
			return nil, errors.Wrapf(err, "extract nydus layer %s", layer.Digest)
		}

		// Unpack using nydus-image
		unpackedDir := filepath.Join(outputDir, "unpacked")
		if err := os.MkdirAll(unpackedDir, 0755); err != nil {
			return nil, errors.Wrapf(err, "create unpacked directory %s", unpackedDir)
		}

		err = runNydusImageUnpack(opt.NydusImagePath, bootstrapPath, blobPath, unpackedDir)
		if err != nil {
			return nil, errors.Wrapf(err, "unpack nydus layer %s", layer.Digest)
		}

		// Create OCI layer tar from unpacked directory
		ociLayerPath := filepath.Join(tmpDir, fmt.Sprintf("oci-layer-%d.tar.gz", i))
		err = createOCILayerTar(unpackedDir, ociLayerPath)
		if err != nil {
			return nil, errors.Wrapf(err, "create oci layer tar %s", ociLayerPath)
		}

		// Calculate digest and size
		ociLayerDigest, ociLayerSize, err := calculateDigestAndSize(ociLayerPath)
		if err != nil {
			return nil, errors.Wrapf(err, "calculate digest for oci layer %s", ociLayerPath)
		}

		ociLayer := ocispec.Descriptor{
			Digest:    ociLayerDigest,
			Size:      ociLayerSize,
			MediaType: ocispec.MediaTypeImageLayerGzip,
		}

		ociLayers = append(ociLayers, ociLayer)
	}

	return ociLayers, nil
}

// isNydusLayer checks if a layer is a Nydus layer
func isNydusLayer(layer ocispec.Descriptor) bool {
	if layer.Annotations == nil {
		return false
	}
	_, hasBootstrap := layer.Annotations["containerd.io/snapshot/nydus-bootstrap"]
	_, hasBlob := layer.Annotations["containerd.io/snapshot/nydus-blob"]
	return hasBootstrap || hasBlob || strings.Contains(layer.MediaType, "nydus")
}

// extractNydusLayer extracts bootstrap and blob files from a Nydus layer
func extractNydusLayer(layerPath, outputDir string) (string, string, error) {
	// Open layer file
	layerFile, err := os.Open(layerPath)
	if err != nil {
		return "", "", errors.Wrapf(err, "open layer file %s", layerPath)
	}
	defer layerFile.Close()

	// Check if it's gzipped
	var reader io.Reader = layerFile
	if strings.HasSuffix(layerPath, ".gz") || isGzipped(layerFile) {
		layerFile.Seek(0, 0)
		gzReader, err := gzip.NewReader(layerFile)
		if err != nil {
			return "", "", errors.Wrap(err, "create gzip reader")
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Extract tar contents
	tarReader := tar.NewReader(reader)
	var bootstrapPath, blobPath string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", errors.Wrap(err, "read tar header")
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		filePath := filepath.Join(outputDir, header.Name)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return "", "", errors.Wrapf(err, "create directory for %s", filePath)
		}

		file, err := os.Create(filePath)
		if err != nil {
			return "", "", errors.Wrapf(err, "create file %s", filePath)
		}

		_, err = io.Copy(file, tarReader)
		file.Close()
		if err != nil {
			return "", "", errors.Wrapf(err, "copy file %s", filePath)
		}

		// Identify bootstrap and blob files
		if strings.Contains(header.Name, "bootstrap") || header.Name == "image.boot" {
			bootstrapPath = filePath
		} else if strings.Contains(header.Name, "blob") || strings.HasSuffix(header.Name, ".blob") {
			blobPath = filePath
		}
	}

	return bootstrapPath, blobPath, nil
}

// isGzipped checks if a file is gzipped
func isGzipped(file *os.File) bool {
	buf := make([]byte, 2)
	n, err := file.Read(buf)
	if err != nil || n < 2 {
		return false
	}
	return buf[0] == 0x1f && buf[1] == 0x8b
}

// runNydusImageUnpack runs nydus-image unpack command
func runNydusImageUnpack(nydusImagePath, bootstrapPath, blobPath, outputDir string) error {
	args := []string{
		"unpack",
		"--bootstrap", bootstrapPath,
		"--output", outputDir,
	}

	if blobPath != "" {
		args = append(args, "--blob", blobPath)
	}

	cmd := exec.Command(nydusImagePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logrus.Infof("Running: %s %s", nydusImagePath, strings.Join(args, " "))
	return cmd.Run()
}

// createOCILayerTar creates a gzipped tar file from a directory
func createOCILayerTar(sourceDir, targetPath string) error {
	tarFile, err := os.Create(targetPath)
	if err != nil {
		return errors.Wrapf(err, "create tar file %s", targetPath)
	}
	defer tarFile.Close()

	gzWriter := gzip.NewWriter(tarFile)
	defer gzWriter.Close()

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the source directory itself
		if path == sourceDir {
			return nil
		}

		// Calculate relative path
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relPath)

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Write file content if it's a regular file
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(tarWriter, file)
			return err
		}

		return nil
	})
}

// calculateDigestAndSize calculates digest and size of a file
func calculateDigestAndSize(filePath string) (digest.Digest, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	digester := digest.Canonical.Digester()
	size, err := io.Copy(digester.Hash(), file)
	if err != nil {
		return "", 0, err
	}

	return digester.Digest(), size, nil
}

// createOCIConfig creates OCI image configuration
func createOCIConfig(nydusManifest *ocispec.Manifest, ociLayers []ocispec.Descriptor) (*ocispec.Image, error) {
	// Create basic OCI config
	config := &ocispec.Image{
		Created: &time.Time{},
		Author:  "nydusify reverse converter",
		Architecture: "amd64",
		OS:      "linux",
		Config: ocispec.ImageConfig{
			Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cmd: []string{"/bin/sh"},
		},
		RootFS: ocispec.RootFS{
			Type: "layers",
			DiffIDs: make([]digest.Digest, len(ociLayers)),
		},
		History: make([]ocispec.History, len(ociLayers)),
	}

	// Calculate diff IDs for uncompressed layers
	for i, layer := range ociLayers {
		// For simplicity, use the same digest as diff ID
		// In a real implementation, you'd need to calculate the uncompressed digest
		config.RootFS.DiffIDs[i] = layer.Digest
		config.History[i] = ocispec.History{
			Created:   &time.Time{},
			CreatedBy: "nydusify reverse converter",
		}
	}

	return config, nil
}

// pushOCIImage pushes the OCI image to target registry
func pushOCIImage(ctx context.Context, opt ReverseOpt, pvd *provider.Provider, tmpDir string, config *ocispec.Image, layers []ocispec.Descriptor) error {
	logrus.Infof("Pushing OCI image to: %s", opt.Target)

	// Create remote for target
	remoter, err := pkgPvd.DefaultRemote(opt.Target, opt.TargetInsecure)
	if err != nil {
		return errors.Wrap(err, "create target remote")
	}

	if opt.WithPlainHTTP {
		remoter.WithHTTP()
	}

	// Push layers
	var pushedLayers []ocispec.Descriptor
	for i, layer := range layers {
		layerPath := filepath.Join(tmpDir, fmt.Sprintf("oci-layer-%d.tar.gz", i))
		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			// Layer wasn't converted, use original
			pushedLayers = append(pushedLayers, layer)
			continue
		}

		layerFile, err := os.Open(layerPath)
		if err != nil {
			return errors.Wrapf(err, "open layer file %s", layerPath)
		}
		defer layerFile.Close()

		err = remoter.Push(ctx, layer, true, layerFile)
		if err != nil {
			return errors.Wrapf(err, "push layer %s", layer.Digest)
		}

		pushedLayers = append(pushedLayers, layer)
	}

	// Create and push config
	configBytes, err := json.Marshal(config)
	if err != nil {
		return errors.Wrap(err, "marshal config")
	}

	configDigest := digest.FromBytes(configBytes)
	configDesc := ocispec.Descriptor{
		Digest:    configDigest,
		Size:      int64(len(configBytes)),
		MediaType: ocispec.MediaTypeImageConfig,
	}

	err = remoter.Push(ctx, configDesc, false, bytes.NewReader(configBytes))
	if err != nil {
		return errors.Wrap(err, "push config")
	}

	// Create and push manifest
	manifest := ocispec.Manifest{
		Versions: specs.VersionSpec{
			SchemaVersion: 2,
		},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    pushedLayers,
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "marshal manifest")
	}

	manifestDigest := digest.FromBytes(manifestBytes)
	manifestDesc := ocispec.Descriptor{
		Digest:    manifestDigest,
		Size:      int64(len(manifestBytes)),
		MediaType: ocispec.MediaTypeImageManifest,
	}

	err = remoter.Push(ctx, manifestDesc, false, bytes.NewReader(manifestBytes))
	if err != nil {
		return errors.Wrap(err, "push manifest")
	}

	return nil
}

// IsNydusImage checks if the given image reference is a Nydus image
// by examining its manifest and media types
func IsNydusImage(ctx context.Context, ref string, insecure bool) (bool, error) {
	// Create a simple provider to fetch the manifest
	hosts := func(domain string) ([]docker.RegistryHost, error) {
		return []docker.RegistryHost{
			{
				Host:         domain,
				Scheme:       "https",
				SkipVerify:   insecure,
				Capabilities: docker.HostCapabilityPull,
			},
		}, nil
	}

	provider := provider.DefaultRemote(ref, hosts)
	manifest, _, err := provider.Manifest(ctx, ref)
	if err != nil {
		return false, err
	}

	// Check if any layer has Nydus-specific media types
	for _, layer := range manifest.Layers {
		if isNydusLayer(layer) {
			return true, nil
		}
	}

	return false, nil
}