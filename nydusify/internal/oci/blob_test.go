/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package oci_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

func TestCommitBlobRetriesInterruptedIngest(t *testing.T) {
	ctx := context.Background()
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	store := provider.ContentStore()
	interrupted := errors.New("interrupted write")
	_, _, err = oci.CommitBlob(ctx, store, "retry", "", nil, func(w io.Writer) error {
		_, err := io.WriteString(w, "partial data longer than the replacement")
		require.NoError(t, err)
		return interrupted
	})
	require.ErrorIs(t, err, interrupted)
	status, err := store.Status(ctx, "retry")
	require.NoError(t, err)
	require.Positive(t, status.Offset)

	data := []byte("replacement")
	expected := digest.FromBytes(data)
	got, size, err := oci.CommitBlob(ctx, store, "retry", expected, nil, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, expected, got)
	require.Equal(t, int64(len(data)), size)
	actual, err := content.ReadBlob(ctx, store, ocispec.Descriptor{Digest: got})
	require.NoError(t, err)
	require.Equal(t, data, actual)
	_, err = store.Status(ctx, "retry")
	require.True(t, errdefs.IsNotFound(err), "committed ingest must be removed: %v", err)
}
