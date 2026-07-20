/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"
	"context"
	"io"
	"os"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/pkg/errors"
)

// ExtractTar extracts a raw (already decompressed) OCI layer tar stream into
// dir using containerd's archive applier.
//
// This performs a verbatim extraction rather than a layered overlay apply: OCI
// whiteout entries (".wh.*") are written out as ordinary files via
// WithConvertWhiteout so that a subsequent `nydus merge` can interpret the
// whiteouts itself. containerd's applier restores ownership, permissions,
// device nodes, hardlinks, timestamps and xattrs in the correct order — in
// particular it sets xattrs after chown, so privileged xattrs such as
// security.capability (for example cap_net_raw on /usr/bin/arping) are not
// stripped by the kernel's chown-time capability clearing.
//
// Faithfully reproducing the layer requires root: ownership (uid/gid), device
// nodes and privileged xattrs cannot otherwise be restored. Rather than
// silently producing an image with the wrong ownership, ExtractTar refuses to
// run unprivileged.
func ExtractTar(ctx context.Context, r io.Reader, dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("converting an image requires root privileges to preserve file ownership and device nodes; re-run with sudo")
	}

	if _, err := archive.Apply(
		ctx,
		dir,
		r,
		archive.WithConvertWhiteout(func(_ *tar.Header, _ string) (bool, error) {
			// Write whiteout entries verbatim instead of applying them as
			// deletions, so `nydus merge` can interpret them later.
			return true, nil
		}),
	); err != nil {
		return errors.Wrap(err, "apply layer tar")
	}

	return nil
}
