//go:build !linux

/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mounter

import "github.com/pkg/errors"

func prepareMountpoint(string) (string, error) {
	return "", errors.New("nydus FUSE mounting is supported only on Linux")
}

func unmountExitedFuse(string, string) error {
	return errors.New("nydus FUSE mounting is supported only on Linux")
}
