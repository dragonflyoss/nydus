// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
)

func CompressTargz(src string, name string, writer io.Writer) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}

	hdr := &tar.Header{
		Name: name,
		Mode: 0666,
		Size: fi.Size(),
	}

	gzw := gzip.NewWriter(writer)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(tw, f); err != nil {
		return err
	}

	return nil
}

func DecompressTargz(dst string, r io.Reader) error {
	ds, err := compression.DecompressStream(r)
	if err != nil {
		return err
	}
	defer ds.Close()

	if err := os.MkdirAll(dst, 0770); err != nil {
		return err
	}

	if _, err := archive.Apply(
		context.Background(),
		dst,
		ds,
		archive.WithConvertWhiteout(func(hdr *tar.Header, file string) (bool, error) {
			return true, nil
		}),
	); err != nil {
		return err
	}

	return nil
}
