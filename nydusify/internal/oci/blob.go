/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// CommitBlob streams a blob into the content store and commits it, tolerating
// content that already exists. write receives the content-store writer; the
// blob digest is computed from the written bytes. expected, when non-empty, is
// verified by the content store on commit. labelsFn, when non-nil, is called
// with the final digest after write has returned and its result is attached as
// content-store labels — this allows labels derived from the written data
// (e.g. an uncompressed digest hashed during write). CommitBlob returns the
// committed digest and size.
func CommitBlob(ctx context.Context, cs content.Store, ref string, expected digest.Digest, labelsFn func(digest.Digest) map[string]string, write func(io.Writer) error) (digest.Digest, int64, error) {
	cw, err := content.OpenWriter(ctx, cs, content.WithRef(ref))
	if err != nil {
		return "", 0, errors.Wrap(err, "open content writer")
	}
	defer func() { _ = cw.Close() }()

	// A writer resumed from an interrupted ingest may hold partial data;
	// restart from a clean slate (mirrors content.Copy).
	if status, err := cw.Status(); err != nil {
		return "", 0, errors.Wrap(err, "get writer status")
	} else if status.Offset > 0 {
		if err := cw.Truncate(0); err != nil {
			return "", 0, errors.Wrap(err, "truncate content writer")
		}
	}

	if err := write(cw); err != nil {
		return "", 0, err
	}

	dgst := cw.Digest()
	var opts []content.Opt
	if labelsFn != nil {
		if labels := labelsFn(dgst); len(labels) > 0 {
			opts = append(opts, content.WithLabels(labels))
		}
	}
	if err := cw.Commit(ctx, 0, expected, opts...); err != nil && !errdefs.IsAlreadyExists(err) {
		return "", 0, errors.Wrap(err, "commit blob")
	}

	info, err := cs.Info(ctx, dgst)
	if err != nil {
		return "", 0, errors.Wrap(err, "stat committed blob")
	}
	return dgst, info.Size, nil
}

// WriteJSON marshals x to JSON and commits it to the content store, returning a
// descriptor derived from oldDesc with the new digest and size.
func WriteJSON(ctx context.Context, cs content.Store, x interface{}, oldDesc ocispec.Descriptor, labels map[string]string) (*ocispec.Descriptor, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return nil, errors.Wrap(err, "marshal json")
	}
	dgst := digest.SHA256.FromBytes(b)
	if _, _, err := CommitBlob(ctx, cs, "nydus-write-json-"+dgst.String(), dgst,
		func(digest.Digest) map[string]string { return labels },
		func(w io.Writer) error {
			_, err := w.Write(b)
			return err
		},
	); err != nil {
		return nil, errors.Wrap(err, "commit json")
	}
	newDesc := oldDesc
	newDesc.Size = int64(len(b))
	newDesc.Digest = dgst
	return &newDesc, nil
}

// IngestBlobFile commits a nydus full blob file into the content store as a
// nydus data blob layer, returning its descriptor. When dgst is empty, the
// digest is computed by streaming the file; otherwise the given digest is
// trusted and verified by the content store on commit.
func IngestBlobFile(ctx context.Context, cs content.Store, path string, dgst digest.Digest) (ocispec.Descriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "open blob file")
	}
	defer func() { _ = f.Close() }()

	if dgst == "" {
		digester := digest.SHA256.Digester()
		if _, err := io.Copy(digester.Hash(), f); err != nil {
			return ocispec.Descriptor{}, errors.Wrap(err, "hash blob file")
		}
		dgst = digester.Digest()

		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return ocispec.Descriptor{}, errors.Wrap(err, "seek blob file")
		}
	}

	// A nydus full blob is uncompressed at the layer level, so its diff id
	// equals the blob digest.
	_, size, err := CommitBlob(ctx, cs, "nydus-local-blob-"+dgst.String(), dgst,
		func(d digest.Digest) map[string]string {
			return map[string]string{nydus.LayerAnnotationUncompressed: d.String()}
		},
		func(w io.Writer) error {
			_, err := io.Copy(w, f)
			return errors.Wrap(err, "copy blob file")
		},
	)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "commit blob to content store")
	}

	return ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    dgst,
		Size:      size,
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed: dgst.String(),
			nydus.LayerAnnotationNydusBlob:    "true",
		},
	}, nil
}

// WriteBootstrapLayer packs bootstrap bytes and per-layer blob meta artifacts
// into a gzip-compressed tar layer (under `image/`) and commits it to the
// content store, returning the bootstrap layer descriptor. If appendFiles is
// non-empty, each file is placed under "image/" alongside image.boot.
func WriteBootstrapLayer(ctx context.Context, cs content.Store, bootstrapData []byte, blobMetas []nydus.BlobMetaFile, appendFiles []nydus.AppendFile) (*ocispec.Descriptor, error) {
	var compressedBuf bytes.Buffer
	compressedDigester := digest.SHA256.Digester()
	uncompressedDigester := digest.SHA256.Digester()

	gw := gzip.NewWriter(io.MultiWriter(&compressedBuf, compressedDigester.Hash()))
	tw := tar.NewWriter(io.MultiWriter(gw, uncompressedDigester.Hash()))

	if err := nydus.WriteBootstrapTar(tw, bootstrapData, blobMetas, appendFiles); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, errors.Wrap(err, "close tar writer")
	}
	if err := gw.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	compressedDigest := compressedDigester.Digest()
	uncompressedDigest := uncompressedDigester.Digest()
	layerBytes := compressedBuf.Bytes()

	if _, _, err := CommitBlob(ctx, cs, "nydus-bootstrap-"+compressedDigest.String(), compressedDigest,
		func(digest.Digest) map[string]string {
			return map[string]string{nydus.LayerAnnotationUncompressed: uncompressedDigest.String()}
		},
		func(w io.Writer) error {
			_, err := w.Write(layerBytes)
			return err
		},
	); err != nil {
		return nil, errors.Wrap(err, "commit bootstrap layer")
	}

	return &ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    compressedDigest,
		Size:      int64(len(layerBytes)),
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed:   uncompressedDigest.String(),
			nydus.LayerAnnotationNydusBootstrap: "true",
			nydus.LayerAnnotationNydusFsVersion: nydus.NydusFsVersion,
		},
	}, nil
}

// OpenDecompressedBlob opens a content-store blob and returns a reader over
// its decompressed bytes (gzip/zstd/uncompressed are auto-detected). Closing
// the returned reader also releases the underlying content-store ReaderAt.
func OpenDecompressedBlob(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (io.ReadCloser, error) {
	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, errors.Wrap(err, "open blob reader")
	}
	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		_ = ra.Close()
		return nil, errors.Wrap(err, "decompress blob")
	}
	return &decompressedBlob{ReadCloser: decompressed, ra: ra}, nil
}

type decompressedBlob struct {
	io.ReadCloser
	ra content.ReaderAt
}

func (b *decompressedBlob) Close() error {
	err := b.ReadCloser.Close()
	if raErr := b.ra.Close(); err == nil {
		err = raErr
	}
	return err
}
