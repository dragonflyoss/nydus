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

	// unitSuffix is the unit type of a daemon and of a preheat.
	unitSuffix = ".service"

	// unitPattern matches every daemon unit. It matches the preheat units
	// too, which daemonIDFromUnit rejects: their names hold no daemon ID.
	unitPattern = unitPrefix + "*" + unitSuffix

	// preheatUnitPrefix prefixes every preheat unit.
	preheatUnitPrefix = unitPrefix + "preheat-"

	// preheatUnitPattern matches every preheat unit.
	preheatUnitPattern = preheatUnitPrefix + "*" + unitSuffix

	// shortIDLength is the length of the daemon ID prefix shown in mount
	// sources.
	shortIDLength = 12
)

// daemonID identifies the daemon of an image: the hex digest of its bootstrap
// layer's chain ID, which names its units and directories.
type daemonID string

// daemonIDFromChainID returns the daemon ID of the image of a chain ID.
func daemonIDFromChainID(chainID string) (daemonID, error) {
	// Only sha256 is accepted, as containerd's chain IDs are: Unit and
	// ChainID rebuild their names from the hex alone.
	d, err := digest.Parse(chainID)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return "", fmt.Errorf("invalid chain id %q: %w", chainID, errdefs.ErrInvalidArgument)
	}

	return daemonID(d.Encoded()), nil
}

// daemonIDFromUnit returns the daemon ID of a daemon unit name.
func daemonIDFromUnit(unit string) (daemonID, bool) {
	hex, ok := strings.CutPrefix(unit, unitPrefix)
	if !ok {
		return "", false
	}

	hex, ok = strings.CutSuffix(hex, unitSuffix)
	if !ok {
		return "", false
	}

	return daemonIDFromHex(hex)
}

// daemonIDFromHex returns the daemon ID a sha256 hex digest is.
func daemonIDFromHex(hex string) (daemonID, bool) {
	if digest.NewDigestFromEncoded(digest.SHA256, hex).Validate() != nil {
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

// PreheatUnit returns the systemd unit of the image's preheat.
func (d daemonID) PreheatUnit() string {
	return preheatUnitPrefix + string(d) + unitSuffix
}

// Short returns the ID prefix shown in mount sources.
func (d daemonID) Short() string {
	return string(d)[:min(len(d), shortIDLength)]
}
