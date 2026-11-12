//go:build !linux

/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import "os/exec"

// DieWithParent is a no-op where a child cannot be bound to its parent.
func DieWithParent(*exec.Cmd) {}
