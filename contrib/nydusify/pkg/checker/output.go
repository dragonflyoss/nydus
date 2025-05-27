// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func prettyDump(obj interface{}, name string) error {
	bytes, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(name, bytes, 0644)
}

// Output outputs OCI and nydus image manifest, index, config to JSON file.
// Prefer to use source image to output OCI image information.
func (checker *Checker) Output(
	ctx context.Context, parsed *parser.Parsed, dir string,
) error {
	logrus.WithField("type", tool.CheckImageType(parsed)).WithField("image", parsed.Remote.Ref).Info("dumping manifest")

	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrap(err, "create output directory")
	}

	if parsed.Index != nil && parsed.OCIImage != nil {
		if err := prettyDump(
			parsed.Index,
			filepath.Join(dir, "oci_index.json"),
		); err != nil {
			return errors.Wrap(err, "output oci index file")
		}
	}

	if parsed.Index != nil && parsed.NydusImage != nil {
		if err := prettyDump(
			parsed.Index,
			filepath.Join(dir, "nydus_index.json"),
		); err != nil {
			return errors.Wrap(err, "output nydus index file")
		}
	}

	if parsed.OCIImage != nil {
		if err := prettyDump(
			parsed.OCIImage.Manifest,
			filepath.Join(dir, "oci_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI manifest file")
		}
		if err := prettyDump(
			parsed.OCIImage.Config,
			filepath.Join(dir, "oci_config.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI config file")
		}
	}

	if parsed.NydusImage != nil {
		if err := prettyDump(
			parsed.NydusImage.Manifest,
			filepath.Join(dir, "nydus_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output nydus manifest file")
		}
		if err := prettyDump(
			parsed.NydusImage.Config,
			filepath.Join(dir, "nydus_config.json"),
		); err != nil {
			return errors.Wrap(err, "output nydus config file")
		}

		bootstrapDir := filepath.Join(dir, "nydus_bootstrap")
		logrus.WithField("type", tool.CheckImageType(parsed)).WithField("image", parsed.Remote.Ref).Info("pulling bootstrap")
		var parser *parser.Parser
		if dir == "source" {
			parser = checker.sourceParser
		} else {
			parser = checker.targetParser
		}
		bootstrapReader, err := parser.PullNydusBootstrap(ctx, parsed.NydusImage)
		if err != nil {
			return errors.Wrap(err, "pull nydus bootstrap layer")
		}
		defer bootstrapReader.Close()

		tarRc, err := compression.DecompressStream(bootstrapReader)
		if err != nil {
			return err
		}
		defer tarRc.Close()

		diffID := digest.SHA256.Digester()
		if err := utils.UnpackFromTar(io.TeeReader(tarRc, diffID.Hash()), bootstrapDir); err != nil {
			return errors.Wrap(err, "unpack nydus bootstrap layer")
		}

		diffIDs := parsed.NydusImage.Config.RootFS.DiffIDs
		manifest := parsed.NydusImage.Manifest
		if manifest.ArtifactType != modelspec.ArtifactTypeModelManifest && diffIDs[len(diffIDs)-1] != diffID.Digest() {
			return errors.Errorf(
				"invalid bootstrap layer diff id: %s (calculated) != %s (in image config)",
				diffID.Digest().String(),
				diffIDs[len(diffIDs)-1].String(),
			)
		}

		if manifest.ArtifactType == modelspec.ArtifactTypeModelManifest {
			if manifest.Subject == nil {
				return errors.New("missing subject in manifest")
			}

			if manifest.Subject.MediaType != ocispec.MediaTypeImageManifest {
				return errors.Errorf("invalid subject media type: %s", manifest.Subject.MediaType)
			}
		}
	}

	return nil
}
