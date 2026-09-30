//go:build !linux

/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import "os"

// growPipe is a no-op where pipe capacity cannot be changed.
func growPipe(*os.File) {}
