/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/errdefs"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

// layer is a parent snapshot with its info.
type layer struct {
	// id is the snapshot ID, the name of its directory.
	id string

	// info is the snapshot info holding its labels.
	info snapshots.Info
}

// mounts returns the mounts of a snapshot. A nydus image's chain is cut at
// its bootstrap: the daemon's mount replaces the bootstrap and data layers.
func (s *snapshotter) mounts(ctx context.Context, snap storage.Snapshot, info snapshots.Info) ([]mount.Mount, error) {
	// A nydus layer being unpacked has only empty data layers below it, so it
	// mounts its own directory instead of a long chain of empty lower dirs.
	if l := labels(info.Labels); snap.Kind == snapshots.KindActive && snapshotKey(info.Name).isUnpack() && (l.isNydusBlob() || l.isNydusBootstrap()) {
		return s.overlayMounts(snap, nil), nil
	}

	// Parents never change while a child exists, so a read transaction of
	// their own sees what the caller's did, and a create's write transaction
	// stays short.
	var layers []layer
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) (err error) {
		layers, err = s.parents(ctx, snap, info)
		return err
	}); err != nil {
		return nil, err
	}

	bootstrap := slices.IndexFunc(layers, func(l layer) bool {
		return labels(l.info.Labels).isNydusBootstrap()
	})

	if bootstrap < 0 {
		if err := s.checkUnlabelledNydus(layers); err != nil {
			return nil, err
		}

		return s.overlayMounts(snap, s.upperPaths(layers)), nil
	}

	mountpoint, err := s.mountImage(ctx, layers[bootstrap])
	if err != nil {
		return nil, err
	}

	return s.overlayMounts(snap, append(s.upperPaths(layers[:bootstrap]), mountpoint)), nil
}

// mountImage ensures the daemon serving the image of a bootstrap layer and
// returns its mountpoint.
func (s *snapshotter) mountImage(ctx context.Context, bootstrap layer) (string, error) {
	bootstrapLabels := labels(bootstrap.info.Labels)
	version := bootstrapLabels[labelNydusFSVersion]
	fileSystem, ok := s.fileSystems[version]
	if !ok {
		return "", fmt.Errorf("nydus image format %s=%q is not supported, convert the image with nydusify v3: %w", labelNydusFSVersion, version, errdefs.ErrNotImplemented)
	}

	chainID := bootstrapLabels[labelSnapshotRef]
	if chainID == "" {
		return "", fmt.Errorf("bootstrap snapshot %s has no %s label: %w", bootstrap.info.Name, labelSnapshotRef, errdefs.ErrFailedPrecondition)
	}

	ref := bootstrapLabels[snapshotters.TargetRefLabel]
	if ref == "" {
		return "", fmt.Errorf("bootstrap snapshot %s has no %s label, set disable_snapshot_annotations = false in containerd's CRI config and pull the image again: %w", bootstrap.info.Name, snapshotters.TargetRefLabel, errdefs.ErrFailedPrecondition)
	}

	scope, err := bootstrapLabels.prefetchScope()
	if err != nil {
		return "", err
	}

	return fileSystem.Mount(ctx, &nydusfs.Image{
		ChainID:       chainID,
		Ref:           ref,
		BootstrapDir:  s.upperPath(bootstrap.id),
		PrefetchScope: scope,
	})
}

// checkUnlabelledNydus fails a chain whose nydus data layers lost their
// bootstrap's labels, a bootstrap unpacked without them (Image.Unpack, CRI's
// fallback unpack, image volumes), which would otherwise run with a rootfs
// holding only image/image.boot.
func (s *snapshotter) checkUnlabelledNydus(layers []layer) error {
	for _, l := range layers {
		if labels(l.info.Labels).isNydusBlob() {
			return fmt.Errorf("snapshot %s is a nydus data layer without a labelled bootstrap, remove the image and pull it through CRI again: %w", l.info.Name, errdefs.ErrFailedPrecondition)
		}
	}

	return nil
}

// overlayMounts returns the mounts of a snapshot over lower dirs, top first,
// as containerd's overlay snapshotter does.
func (s *snapshotter) overlayMounts(snap storage.Snapshot, lowers []string) []mount.Mount {
	// overlayfs needs a lower dir; without one, bind the snapshot's own dir.
	if len(lowers) == 0 {
		mode := "rw"
		if snap.Kind == snapshots.KindView {
			mode = "ro"
		}

		return []mount.Mount{{
			Type:    "bind",
			Source:  s.upperPath(snap.ID),
			Options: []string{mode, "rbind"},
		}}
	}

	var options []string
	if snap.Kind == snapshots.KindActive {
		options = append(options,
			"workdir="+s.workPath(snap.ID),
			"upperdir="+s.upperPath(snap.ID),
		)
	} else if len(lowers) == 1 {
		// overlayfs refuses a read-only mount with one lower dir and no upper.
		return []mount.Mount{{
			Type:    "bind",
			Source:  lowers[0],
			Options: []string{"ro", "rbind"},
		}}
	}

	options = append(options, "lowerdir="+strings.Join(lowers, ":"))
	options = append(options, s.options...)

	return []mount.Mount{{
		Type:    "overlay",
		Source:  "overlay",
		Options: options,
	}}
}

// upperPaths returns the fs directories of layers.
func (s *snapshotter) upperPaths(layers []layer) []string {
	paths := make([]string, 0, len(layers))
	for _, l := range layers {
		paths = append(paths, s.upperPath(l.id))
	}

	return paths
}

// parents returns the parent chain of a snapshot, the immediate parent first.
// It runs in a metadata transaction.
func (s *snapshotter) parents(ctx context.Context, snap storage.Snapshot, info snapshots.Info) ([]layer, error) {
	layers := make([]layer, 0, len(snap.ParentIDs))
	name := info.Parent
	for _, id := range snap.ParentIDs {
		_, parent, _, err := storage.GetInfo(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("get parent %s: %w", name, err)
		}

		layers = append(layers, layer{id: id, info: parent})
		name = parent.Parent
	}

	return layers, nil
}
