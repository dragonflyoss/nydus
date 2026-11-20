/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package version holds the build information injected with -ldflags.
package version

import "fmt"

var (
	// GitVersion is the release version, e.g. v0.1.0.
	GitVersion = "unknown"

	// GitCommit is the git commit of the build.
	GitCommit = "unknown"

	// BuildTime is the UTC build time.
	BuildTime = "unknown"
)

// String returns the version line printed by the version flag.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", GitVersion, GitCommit, BuildTime)
}
