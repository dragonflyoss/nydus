// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

func prettyDump(obj interface{}, name string) error {
	bytes, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(name, bytes, 0644)
}

// Output outputs OCI and Nydus image manifest, index, config to JSON file.
// Prefer to use source image to output OCI image information.
func (checker *Checker) Output(
	ctx context.Context, sourceParsed, targetParsed *parser.Parsed, outputPath string,
) error {
	logrus.Infof("Dumping OCI and Nydus manifests to %s", outputPath)

	if targetParsed.Index != nil {
		if err := prettyDump(
			targetParsed.Index,
			filepath.Join(outputPath, "index.json"),
		); err != nil {
			return errors.Wrap(err, "output index file")
		}
	}

	if sourceParsed.OCIImage != nil {
		if err := prettyDump(
			sourceParsed.OCIImage.Manifest,
			filepath.Join(outputPath, "oci_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI manifest file")
		}
		if err := prettyDump(
			sourceParsed.OCIImage.Config,
			filepath.Join(outputPath, "oci_config.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI config file")
		}
	}

	if targetParsed.NydusImage != nil {
		if err := prettyDump(
			targetParsed.NydusImage.Manifest,
			filepath.Join(outputPath, "nydus_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus manifest file")
		}
		if err := prettyDump(
			targetParsed.NydusImage.Config,
			filepath.Join(outputPath, "nydus_config.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus config file")
		}

		target := filepath.Join(outputPath, "nydus_bootstrap")
		logrus.Infof("Pulling Nydus bootstrap to %s", target)
		bootstrapReader, err := checker.targetParser.PullNydusBootstrap(ctx, targetParsed.NydusImage)
		if err != nil {
			return errors.Wrap(err, "pull Nydus bootstrap layer")
		}
		defer bootstrapReader.Close()

		if err := utils.UnpackFile(bootstrapReader, utils.BootstrapFileNameInLayer, target); err != nil {
			return errors.Wrap(err, "unpack Nydus bootstrap layer")
		}
	}

	return nil
}
