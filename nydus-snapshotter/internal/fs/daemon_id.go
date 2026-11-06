/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"fmt"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
)

const (
	// unitPrefix prefixes every daemon unit.
	unitPrefix = "nydusd-"

	// unitSuffix is the unit type of a daemon.
	unitSuffix = ".service"

	// unitPattern matches every daemon unit.
	unitPattern = unitPrefix + "*" + unitSuffix

	// shortIDLength is the daemon ID prefix shown in mount sources.
	shortIDLength = 12
)

// daemonID identifies the daemon of an image: the hex digest of its bootstrap
// layer's chain ID, which names its unit and directories.
type daemonID string

// parseDaemonID returns the daemon ID of a chain ID.
func parseDaemonID(chainID string) (daemonID, error) {
	// Units and ChainID assume sha256, as containerd's chain IDs are.
	d, err := digest.Parse(chainID)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return "", fmt.Errorf("invalid chain id %q: %w", chainID, errdefs.ErrInvalidArgument)
	}

	return daemonID(d.Encoded()), nil
}

// daemonIDOfUnit returns the daemon ID of a daemon unit name.
func daemonIDOfUnit(unit string) (daemonID, bool) {
	hex, ok := strings.CutPrefix(unit, unitPrefix)
	if !ok {
		return "", false
	}

	hex, ok = strings.CutSuffix(hex, unitSuffix)
	if !ok || digest.NewDigestFromEncoded(digest.SHA256, hex).Validate() != nil {
		return "", false
	}

	return daemonID(hex), true
}

// ChainID returns the chain ID of the image.
func (d daemonID) ChainID() string {
	return digest.NewDigestFromEncoded(digest.SHA256, string(d)).String()
}

// Unit returns the systemd unit of the daemon.
func (d daemonID) Unit() string {
	return unitPrefix + string(d) + unitSuffix
}

// Short returns the ID prefix shown in mount sources.
func (d daemonID) Short() string {
	return string(d)[:min(len(d), shortIDLength)]
}
