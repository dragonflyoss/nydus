/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import "github.com/pkg/errors"

// ConvertInput describes the mutually exclusive input modes accepted by
// nydusify convert. Normal source mode builds from --source; artifact mode
// packages an existing bootstrap with local blobs or parent image blobs.
type ConvertInput struct {
	Sources       []string
	BootstrapPath string
	BlobPaths     []string
	BlobDir       string
	ParentImages  []string
}

// ValidateConvertInputs validates the input mode and reports whether artifact
// packaging mode should be used.
func ValidateConvertInputs(input ConvertInput) (bool, error) {
	artifactMode := input.BootstrapPath != "" || len(input.BlobPaths) > 0 || input.BlobDir != "" || len(input.ParentImages) > 0
	if len(input.Sources) == 0 && !artifactMode {
		return false, errors.New("either --source or artifact inputs (--bootstrap with --blob/--blob-dir/--parent-image) is required")
	}
	if len(input.Sources) > 0 && artifactMode {
		return false, errors.New("--source cannot be combined with artifact inputs (--bootstrap/--blob/--blob-dir/--parent-image)")
	}
	if !artifactMode {
		return false, nil
	}
	if input.BootstrapPath == "" {
		return false, errors.New("--bootstrap is required when using --blob, --blob-dir, or --parent-image")
	}
	if len(input.BlobPaths) == 0 && input.BlobDir == "" && len(input.ParentImages) == 0 {
		return false, errors.New("at least one of --blob, --blob-dir, or --parent-image is required with --bootstrap")
	}
	if len(input.ParentImages) > 1 {
		return false, errors.New("only one --parent-image is supported")
	}
	return true, nil
}
