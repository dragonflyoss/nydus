/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination driver_mock_test.go -source driver.go -package fs

package fs

import (
	"fmt"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

// Driver is how a v3 daemon mounts an image, the seam where further nydus
// mount modes plug in; fuse is the one implemented.
type Driver interface {
	// Name returns the driver name recorded in instances.
	Name() string

	// Args returns the daemon's arguments after the nydus binary.
	Args(d *Daemon) []string

	// Environment returns the daemon's KEY=VALUE variables.
	Environment() []string

	// Mounted reports whether the daemon's mount is in place.
	Mounted(d *Daemon) (bool, error)

	// Unmount detaches what the daemon's mount left behind once the daemon
	// stopped, a stale mount included; an absent mount is not an error.
	Unmount(d *Daemon) error
}

// newDriver returns the driver of a name.
func newDriver(name string) (Driver, error) {
	switch name {
	case config.DriverFuse:
		return &fuseDriver{}, nil
	default:
		return nil, fmt.Errorf("unsupported driver %q", name)
	}
}
