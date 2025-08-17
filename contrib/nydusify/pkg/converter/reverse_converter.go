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

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/goharbor/acceleration-service/pkg/platformutil"

	// Import snapshotter converter package for Unpack function
	snapshotterConverter "github.com/containerd/nydus-snapshotter/pkg/converter"
)

// execCommand is a variable that can be replaced in tests
var execCommand = exec.Command

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
	PushRetryDelay int
	WithPlainHTTP  bool
}

// ReverseConvert converts Nydus image to OCI image
func ReverseConvert(ctx context.Context, opt ReverseOpt) error {
	logrus.Infof("Starting reverse conversion from Nydus image %s to OCI image %s", opt.Source, opt.Target)

	ctx = namespaces.WithNamespace(ctx, "nydusify")
	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return errors.Wrap(err, "parse platforms")
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

	// Parse retry delay (convert seconds to duration)
	retryDelay := time.Duration(opt.PushRetryDelay) * time.Second

	// Set push retry configuration
	pvd.SetPushRetryConfig(opt.PushRetryCount, retryDelay)

	// Step 1: Pull Nydus image and extract layers
	nydusLayers, originalConfig, err := pullNydusImage(ctx, opt, pvd, tmpDir)
	if err != nil {
		return errors.Wrap(err, "pull nydus image")
	}

	// Step 2: Unpack Nydus layers to OCI format
	ociLayers, err := unpackNydusLayers(ctx, opt, tmpDir, nydusLayers)
	if err != nil {
		return errors.Wrap(err, "unpack nydus layers")
	}

	// Step 3: Create OCI image config
	ociConfig, err := createOCIConfig(originalConfig, ociLayers)
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
func pullNydusImage(ctx context.Context, opt ReverseOpt, _ *provider.Provider, tmpDir string) ([]ocispec.Descriptor, *ocispec.Image, error) {
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

	// Pull image config
	configReader, err := remoter.Pull(ctx, manifest.Config, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "pull nydus image config")
	}
	defer configReader.Close()

	configBytes, err := io.ReadAll(configReader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read config bytes")
	}

	var config ocispec.Image
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal image config")
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

	return layers, &config, nil
}

// unpackNydusLayers unpacks Nydus layers using converter.Unpack function
func unpackNydusLayers(ctx context.Context, _ ReverseOpt, tmpDir string, nydusLayers []ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	logrus.Info("Unpacking Nydus layers to OCI format")

	var ociLayers []ocispec.Descriptor

	for _, layer := range nydusLayers {
		// Skip non-nydus layers
		if !isNydusLayer(layer) {
			ociLayers = append(ociLayers, layer)
			continue
		}

		// Skip the nydus bootstrap layer
		if snapshotterConverter.IsNydusBootstrap(layer) {
			logrus.Debugf("skip nydus bootstrap layer %s", layer.Digest.String())
			continue // Don't add bootstrap to OCI layers
		}

		layerPath := filepath.Join(tmpDir, layer.Digest.Hex())

		// Use local.OpenReader to get content.ReaderAt
		ra, err := local.OpenReader(layerPath)
		if err != nil {
			return nil, errors.Wrapf(err, "open layer file %s", layerPath)
		}
		defer ra.Close()

		// Create output file for the unpacked OCI layer using the original digest as filename
		ociLayerPath := filepath.Join(tmpDir, fmt.Sprintf("oci-layer-%s.tar.gz", layer.Digest.Hex()))
		ociLayerFile, err := os.Create(ociLayerPath)
		if err != nil {
			return nil, errors.Wrapf(err, "create oci layer file %s", ociLayerPath)
		}

		// Create gzip writer for compression
		gzipWriter := gzip.NewWriter(ociLayerFile)

		// Create digesters for uncompressed data only (for DiffIDs)
		uncompressedDigester := digest.SHA256.Digester()

		// Use a multi-writer to both write to gzip and calculate uncompressed digest
		unpackWriter := io.MultiWriter(gzipWriter, uncompressedDigester.Hash())

		// Unpack the nydus layer to uncompressed tar data
		unpackOpt := snapshotterConverter.UnpackOption{
			WorkDir: tmpDir,
			Stream:  false, // Use non-streaming mode for simplicity
		}

		err = snapshotterConverter.Unpack(ctx, ra, unpackWriter, unpackOpt)
		if err != nil {
			gzipWriter.Close()
			ociLayerFile.Close()
			return nil, errors.Wrapf(err, "unpack nydus layer %s", layer.Digest)
		}

		// Close gzip writer to finalize compression
		err = gzipWriter.Close()
		if err != nil {
			ociLayerFile.Close()
			return nil, errors.Wrapf(err, "close gzip writer for layer %s", layer.Digest)
		}

		err = ociLayerFile.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "close oci layer file %s", ociLayerPath)
		}

		// Calculate compressed digest and size from the actual file
		compressedDigest, fileSize, err := calculateDigestAndSize(ociLayerPath)
		if err != nil {
			return nil, errors.Wrapf(err, "calculate digest and size for %s", ociLayerPath)
		}

		// Get uncompressed digest
		uncompressedDigest := uncompressedDigester.Digest()

		// Create OCI layer descriptor
		ociLayer := ocispec.Descriptor{
			Digest:    compressedDigest,
			Size:      fileSize,
			MediaType: ocispec.MediaTypeImageLayerGzip,
			// Store uncompressed digest for DiffIDs calculation and original digest for file mapping
			Annotations: map[string]string{
				"io.containerd.uncompressed":      uncompressedDigest.String(),
				"io.nydusify.source.layer.digest": layer.Digest.String(),
			},
		}

		ociLayers = append(ociLayers, ociLayer)

		logrus.Infof("Successfully converted nydus layer %s to oci layer %s", layer.Digest, ociLayer.Digest)
	}

	return ociLayers, nil
}

// isNydusLayer checks if a layer is a Nydus layer
func isNydusLayer(layer ocispec.Descriptor) bool {
	if layer.MediaType == "application/vnd.oci.image.layer.nydus.blob.v1" {
		return true
	}
	if layer.Annotations == nil {
		return false
	}
	_, hasBootstrap := layer.Annotations["containerd.io/snapshot/nydus-bootstrap"]
	_, hasBlob := layer.Annotations["containerd.io/snapshot/nydus-blob"]
	return hasBootstrap || hasBlob
}

// nolint: unused
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
func createOCIConfig(originalConfig *ocispec.Image, ociLayers []ocispec.Descriptor) (*ocispec.Image, error) {
	// Use current UTC time
	now := time.Now().UTC()

	// Copy all information from original config, preserving everything
	config := &ocispec.Image{
		Created:  &now,
		Author:   originalConfig.Author,
		Platform: originalConfig.Platform,
		Config:   originalConfig.Config,
		RootFS: ocispec.RootFS{
			Type:    originalConfig.RootFS.Type,
			DiffIDs: make([]digest.Digest, len(ociLayers)),
		},
		// Preserve original history completely
		History: make([]ocispec.History, len(ociLayers)),
	}

	// Calculate diff IDs for uncompressed layers
	for i, layer := range ociLayers {
		// Use uncompressed digest for DiffIDs
		if uncompressedDigestStr, ok := layer.Annotations["io.containerd.uncompressed"]; ok {
			uncompressedDigest, err := digest.Parse(uncompressedDigestStr)
			if err != nil {
				return nil, errors.Wrapf(err, "parse uncompressed digest %s", uncompressedDigestStr)
			}
			config.RootFS.DiffIDs[i] = uncompressedDigest
		} else {
			// Fallback to layer digest for non-nydus layers
			config.RootFS.DiffIDs[i] = layer.Digest
		}

		if i < len(originalConfig.History) {
			config.History[i] = originalConfig.History[i]
		} else {
			// Use current UTC time for new layers
			now := time.Now().UTC()
			config.History[i] = ocispec.History{
				Created:   &now,
				CreatedBy: "nydusify reverse converter",
			}
		}
	}

	return config, nil
}

// pushOCIImage pushes the OCI image to target registry
func pushOCIImage(ctx context.Context, opt ReverseOpt, _ *provider.Provider, tmpDir string, config *ocispec.Image, layers []ocispec.Descriptor) error {
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
	for _, layer := range layers {
		// Check if this layer was converted (has source digest annotation)
		sourceDigest, hasSourceDigest := layer.Annotations["io.nydusify.source.layer.digest"]
		if hasSourceDigest {
			// Parse the source digest to get the hex part only
			parsedDigest, err := digest.Parse(sourceDigest)
			if err != nil {
				return errors.Wrapf(err, "parse source digest %s", sourceDigest)
			}

			// This is a converted layer, find the corresponding file
			layerPath := filepath.Join(tmpDir, fmt.Sprintf("oci-layer-%s.tar.gz", parsedDigest.Hex()))
			if _, err := os.Stat(layerPath); os.IsNotExist(err) {
				return errors.Wrapf(err, "converted layer file not found: %s", layerPath)
			}

			layerFile, err := os.Open(layerPath)
			if err != nil {
				return errors.Wrapf(err, "open layer file %s", layerPath)
			}
			defer layerFile.Close()

			// Use the layer descriptor which already has the correct digest and size from conversion
			err = remoter.Push(ctx, layer, true, layerFile)
			if err != nil {
				return errors.Wrapf(err, "push layer %s", layer.Digest)
			}
		} else {
			// This is an original layer (non-Nydus or skipped), push from original file
			// For now, we'll just add it to pushed layers without actually pushing
			// as these layers should already exist in the registry
			logrus.Infof("Skipping push for original layer %s (should already exist)", layer.Digest)
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
		Versioned: specs.Versioned{
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
