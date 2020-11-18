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

func CompressTargz(src string, name string, compress bool) (io.ReadCloser, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}

	hdr := &tar.Header{
		Name: name,
		Mode: 0666,
		Size: fi.Size(),
	}

	reader, writer := io.Pipe()

	go func() error {
		// Prepare targz writer
		var tw *tar.Writer
		var gw *gzip.Writer

		if compress {
			gw = gzip.NewWriter(writer)
			tw = tar.NewWriter(gw)
		} else {
			tw = tar.NewWriter(writer)
		}

		file, err := os.Open(src)
		if err != nil {
			return writer.CloseWithError(err)
		}
		defer file.Close()

		// Write targz stream
		if err := tw.WriteHeader(hdr); err != nil {
			return writer.CloseWithError(err)
		}

		if _, err := io.Copy(tw, file); err != nil {
			return writer.CloseWithError(err)
		}

		// Close all resources
		if err := tw.Close(); err != nil {
			return writer.CloseWithError(err)
		}
		if gw != nil {
			if err := gw.Close(); err != nil {
				return writer.CloseWithError(err)
			}
		}

		return writer.CloseWithError(nil)
	}()

	return reader, nil
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
