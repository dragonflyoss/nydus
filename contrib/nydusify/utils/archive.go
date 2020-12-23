// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
)

func CompressTargz(src string, name string, compress bool) (io.ReadCloser, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}

	dirHdr := &tar.Header{
		Name:     filepath.Dir(name),
		Mode:     0770,
		Typeflag: tar.TypeDir,
	}

	hdr := &tar.Header{
		Name: name,
		Mode: 0666,
		Size: fi.Size(),
	}

	reader, writer := io.Pipe()

	go func() {
		// Prepare targz writer
		var tw *tar.Writer
		var gw *gzip.Writer
		var err error
		var file *os.File

		if compress {
			gw = gzip.NewWriter(writer)
			tw = tar.NewWriter(gw)
		} else {
			tw = tar.NewWriter(writer)
		}

		defer func() {
			err1 := tw.Close()
			var err2 error
			if gw != nil {
				err2 = gw.Close()
			}

			var finalErr error

			// Return the first error encountered to the other end and ignore others.
			if err != nil {
				finalErr = err
			} else if err1 != nil {
				finalErr = err1
			} else if err2 != nil {
				finalErr = err2
			}

			writer.CloseWithError(finalErr)
		}()

		file, err = os.Open(src)
		if err != nil {
			return
		}
		defer file.Close()

		// Write targz stream
		if err = tw.WriteHeader(dirHdr); err != nil {
			return
		}

		if err = tw.WriteHeader(hdr); err != nil {
			return
		}

		if _, err = io.Copy(tw, file); err != nil {
			return
		}
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

func UnpackFile(reader io.Reader, source, target string) error {
	rdr, err := compression.DecompressStream(reader)
	if err != nil {
		return err
	}
	defer rdr.Close()

	found := false
	tr := tar.NewReader(rdr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		if hdr.Name == source {
			file, err := os.Create(target)
			if err != nil {
				return err
			}
			defer file.Close()
			if _, err := io.Copy(file, tr); err != nil {
				return err
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Not found file %s in targz", source)
	}

	return nil
}
