/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Nydus-snapshotter is a containerd proxy snapshotter for Nydus v3 images. It
// runs one nydus daemon per image as a transient systemd unit, and installs
// itself onto a Kubernetes node with its install command.
package main

import "github.com/dragonflyoss/nydus/nydus-snapshotter/cmd/nydus-snapshotter/cmd"

func main() {
	cmd.Execute()
}
