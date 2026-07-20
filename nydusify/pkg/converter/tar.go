/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"

	"github.com/pkg/errors"
)

// WriteBootstrapTar writes the `image/` directory, the `image/image.boot` file,
// one `image/<full_blob_sha256>.blob.meta` entry per layer, and optionally
// extra appended files into tw. The caller owns tw and must close it.
func WriteBootstrapTar(tw *tar.Writer, bootstrapData []byte, blobMetas []BlobMetaFile, appendFiles []AppendFile) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:     "image",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		return errors.Wrap(err, "write bootstrap dir header")
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: BootstrapFileNameInLayer,
		Mode: 0o444,
		Size: int64(len(bootstrapData)),
	}); err != nil {
		return errors.Wrap(err, "write bootstrap file header")
	}
	if _, err := tw.Write(bootstrapData); err != nil {
		return errors.Wrap(err, "write bootstrap file")
	}
	for _, meta := range blobMetas {
		if err := tw.WriteHeader(&tar.Header{
			Name: BlobMetaDirInLayer + "/" + meta.Name,
			Mode: 0o444,
			Size: int64(len(meta.Data)),
		}); err != nil {
			return errors.Wrapf(err, "write blob meta header %s", meta.Name)
		}
		if _, err := tw.Write(meta.Data); err != nil {
			return errors.Wrapf(err, "write blob meta %s", meta.Name)
		}
	}
	for _, f := range appendFiles {
		if err := tw.WriteHeader(&tar.Header{
			Name: "image/" + f.Name,
			Mode: 0o444,
			Size: int64(len(f.Data)),
		}); err != nil {
			return errors.Wrapf(err, "write appended file header %s", f.Name)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return errors.Wrapf(err, "write appended file %s", f.Name)
		}
	}
	return nil
}
