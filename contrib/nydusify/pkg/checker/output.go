// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/pkg/checker/parser"
	"contrib/nydusify/pkg/utils"
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
func (checker *Checker) Output(sourceParsed, targetParsed *parser.Parsed, outputPath string) error {
	logrus.Infof("Dumping OCI and Nydus manifests to %s", outputPath)

	if targetParsed.Index != nil {
		if err := prettyDump(
			targetParsed.Index,
			filepath.Join(outputPath, "index.json"),
		); err != nil {
			return errors.Wrap(err, "output index file")
		}
	}

	if sourceParsed.OCIManifest != nil {
		if err := prettyDump(
			sourceParsed.OCIManifest,
			filepath.Join(outputPath, "oci_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI manifest file")
		}
	}

	if sourceParsed.OCIConfig != nil {
		if err := prettyDump(
			sourceParsed.OCIConfig,
			filepath.Join(outputPath, "oci_config.json"),
		); err != nil {
			return errors.Wrap(err, "output OCI config file")
		}
	}

	if targetParsed.NydusManifest != nil {
		if err := prettyDump(
			targetParsed.NydusManifest,
			filepath.Join(outputPath, "nydus_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus manifest file")
		}
	}

	if targetParsed.NydusConfig != nil {
		if err := prettyDump(
			targetParsed.NydusConfig,
			filepath.Join(outputPath, "nydus_config.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus config file")
		}
	}

	if targetParsed.NydusBootstrap != nil {
		target := filepath.Join(outputPath, "nydus_bootstrap")
		logrus.Infof("Pulling Nydus bootstrap to %s", target)
		if err := utils.UnpackFile(targetParsed.NydusBootstrap, utils.BootstrapFileNameInLayer, target); err != nil {
			return errors.Wrap(err, "unpack Nydus bootstrap layer")
		}
		defer targetParsed.NydusBootstrap.Close()
	}

	return nil
}
