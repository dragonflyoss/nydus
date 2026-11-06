/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

const (
	// labelSnapshotRef is the chain ID the unpacker prepares a layer for, a
	// private constant of containerd's unpacker before v2.4, refer to
	// https://github.com/containerd/containerd/blob/v2.2.10/core/unpack/unpacker.go.
	labelSnapshotRef = "containerd.io/snapshot.ref"

	// labelNydusBlob marks a nydus data layer, set by nydusify, refer to
	// nydusify/pkg/nydus/constants.go.
	labelNydusBlob = "containerd.io/snapshot/nydus-blob"

	// labelNydusBootstrap marks the nydus bootstrap layer, set by nydusify.
	labelNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"

	// labelNydusFSVersion is the nydus format of the bootstrap layer.
	labelNydusFSVersion = "containerd.io/snapshot/nydus-fs-version"

	// labelNydusPrefetch overrides the daemon's prefetch scope, set at pull.
	labelNydusPrefetch = "containerd.io/snapshot/nydus-prefetch"

	// labelTrue is the value of a set boolean label.
	labelTrue = "true"
)

// snapshotKey is a backend snapshot key. containerd's metadata store
// prefixes keys with <namespace>/<id>/, refer to
// https://github.com/containerd/containerd/blob/v2.2.10/core/metadata/snapshot.go.
type snapshotKey string

// isUnpack reports whether the key is one containerd's unpacker prepares a
// layer with, the only keys whose remote labels are honoured, so container
// annotations cannot forge a committed snapshot.
func (k snapshotKey) isUnpack() bool {
	key := string(k)
	if parts := strings.SplitN(key, "/", 3); len(parts) == 3 {
		key = parts[2]
	}

	return strings.HasPrefix(key, snapshots.UnpackKeyPrefix+"-")
}

// labels are the labels of a snapshot.
type labels map[string]string

// isNydusBlob reports whether the labels mark a nydus data layer.
func (l labels) isNydusBlob() bool {
	return l[labelNydusBlob] == labelTrue
}

// isNydusBootstrap reports whether the labels mark a nydus bootstrap layer.
func (l labels) isNydusBootstrap() bool {
	return l[labelNydusBootstrap] == labelTrue
}

// prefetchScope returns the prefetch scope a bootstrap's labels ask for, ""
// for the configured default.
func (l labels) prefetchScope() (string, error) {
	scope, ok := l[labelNydusPrefetch]
	if !ok {
		return "", nil
	}

	if !slices.Contains(config.PrefetchScopes, scope) {
		return "", fmt.Errorf("label %s=%q, want one of %s: %w", labelNydusPrefetch, scope, strings.Join(config.PrefetchScopes, ", "), errdefs.ErrInvalidArgument)
	}

	return scope, nil
}

// rootPair returns the host uid and gid container root maps to under the
// uid/gid mapping labels of a user namespace, and whether the labels are set.
// The format is containerd's, "<container id>:<host id>:<size>" ranges joined
// by commas, refer to
// https://github.com/containerd/containerd/blob/v2.2.10/internal/userns/idmap.go.
func (l labels) rootPair() (uid, gid int, ok bool, err error) {
	uidMap, hasUID := l[snapshots.LabelSnapshotUIDMapping]
	gidMap, hasGID := l[snapshots.LabelSnapshotGIDMapping]
	if !hasUID && !hasGID {
		return 0, 0, false, nil
	}

	uid, err = idMapping(uidMap).rootID()
	if err != nil {
		return 0, 0, false, fmt.Errorf("label %s: %w", snapshots.LabelSnapshotUIDMapping, err)
	}

	gid, err = idMapping(gidMap).rootID()
	if err != nil {
		return 0, 0, false, fmt.Errorf("label %s: %w", snapshots.LabelSnapshotGIDMapping, err)
	}

	return uid, gid, true, nil
}

// idMapping is a uid or gid mapping label value.
type idMapping string

// rootID returns the host ID container ID 0 maps to; an empty mapping maps 0
// to itself.
func (m idMapping) rootID() (int, error) {
	if m == "" {
		return 0, nil
	}

	for r := range strings.SplitSeq(string(m), ",") {
		var containerID, hostID, size uint32
		if _, err := fmt.Sscanf(r, "%d:%d:%d", &containerID, &hostID, &size); err != nil {
			return 0, fmt.Errorf("parse id mapping %q: %w", r, errdefs.ErrInvalidArgument)
		}

		if containerID == 0 && size > 0 {
			return int(hostID), nil
		}
	}

	return 0, fmt.Errorf("id mapping %q does not map container root: %w", m, errdefs.ErrInvalidArgument)
}
