/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

func mountRule(t *testing.T, builder string) (filesystemRule, *nydusfs.Image) {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
	require.NoError(t, err)
	boot, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("bootstrap"), nil, nil)
	require.NoError(t, err)
	img := &nydusfs.Image{Ref: "registry.invalid/source:tag", Kind: nydusfs.KindNydus, Bootstrap: boot}
	return filesystemRule{cs: provider.ContentStore(), provider: provider, builder: builder, workDir: t.TempDir()}, img
}
