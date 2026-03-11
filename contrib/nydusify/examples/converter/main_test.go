package main

import (
	"context"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"

	converterpkg "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter"
)

func TestMain(t *testing.T) {
	patches := gomonkey.ApplyFunc(converterpkg.Convert, func(ctx context.Context, opt converterpkg.Opt) error {
		require.Equal(t, "./tmp", opt.WorkDir)
		require.Equal(t, "/path/to/nydus-image", opt.NydusImagePath)
		require.Equal(t, "localhost:5000/ubuntu:latest", opt.Source)
		require.Equal(t, "localhost:5000/ubuntu:latest-nydus", opt.Target)
		require.True(t, opt.SourceInsecure)
		require.True(t, opt.TargetInsecure)
		require.Equal(t, "linux/amd64", opt.Platforms)
		return nil
	})
	defer patches.Reset()

	main()
}
