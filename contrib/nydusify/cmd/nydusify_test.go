// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestIsPossibleValue(t *testing.T) {
	value := "qwe"
	list := []string{"abc", "qwe", "xyz"}
	require.True(t, isPossibleValue(list, value))

	// Failure situation
	value2 := "vdf"
	require.False(t, isPossibleValue(list, value2))
}

func TestAddReferenceSuffix(t *testing.T) {
	source := "localhost:5000/nginx:latest"
	suffix := "-suffix"
	target, err := addReferenceSuffix(source, suffix)
	require.NoError(t, err)
	require.Equal(t, target, "localhost:5000/nginx:latest-suffix")

	// Failure situation
	source = "localhost:5000\nginx:latest"
	suffix = "-suffix"
	_, err = addReferenceSuffix(source, suffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid source image reference")

	source = "localhost:5000/nginx:latest@sha256:757574c5a2102627de54971a0083d4ecd24eb48fdf06b234d063f19f7bbc22fb"
	suffix = "-suffix"
	_, err = addReferenceSuffix(source, suffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported digested image reference")
}

func TestParseBackendConfig(t *testing.T) {
	configJSON := `
	{
		"bucket_name": "test",
		"endpoint": "region.oss.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"meta_prefix": "meta",
		"blob_prefix": "blob"
	}`
	require.True(t, json.Valid([]byte(configJSON)))

	file, err := os.CreateTemp("", "nydusify-backend-config-test.json")
	require.NoError(t, err)
	defer os.RemoveAll(file.Name())

	_, err = file.WriteString(configJSON)
	require.NoError(t, err)
	file.Sync()

	resultJSON, err := parseBackendConfig("", file.Name())
	require.NoError(t, err)
	require.True(t, json.Valid([]byte(resultJSON)))
	require.Equal(t, configJSON, resultJSON)

	// Failure situation
	_, err = parseBackendConfig(configJSON, file.Name())
	require.Error(t, err)

	_, err = parseBackendConfig("", "non-existent.json")
	require.Error(t, err)
}

func TestGetBackendConfig(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "prefixbackend-type",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "prefixbackend-config",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "prefixbackend-config-file",
				Value: "",
			},
		},
	}
	ctx := cli.NewContext(app, nil, nil)

	backendType, backendConfig, err := getBackendConfig(ctx, "prefix", false)
	require.NoError(t, err)
	require.Empty(t, backendType)
	require.Empty(t, backendConfig)

	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "backend type is empty, please specify option")
	require.Empty(t, backendType)
	require.Empty(t, backendConfig)

	flagSet := flag.NewFlagSet("test1", flag.PanicOnError)
	flagSet.String("prefixbackend-type", "errType", "")
	ctx = cli.NewContext(app, flagSet, nil)
	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "backend-type should be one of")
	require.Empty(t, backendType)
	require.Empty(t, backendConfig)

	flagSet = flag.NewFlagSet("test2", flag.PanicOnError)
	flagSet.String("prefixbackend-type", "oss", "")
	ctx = cli.NewContext(app, flagSet, nil)
	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "backend configuration is empty, please specify option")
	require.Empty(t, backendType)
	require.Empty(t, backendConfig)

	configJSON := `
	{
		"bucket_name": "test",
		"endpoint": "region.oss.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"meta_prefix": "meta",
		"blob_prefix": "blob"
	}`
	require.True(t, json.Valid([]byte(configJSON)))

	flagSet = flag.NewFlagSet("test3", flag.PanicOnError)
	flagSet.String("prefixbackend-type", "oss", "")
	flagSet.String("prefixbackend-config", configJSON, "")
	ctx = cli.NewContext(app, flagSet, nil)
	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.NoError(t, err)
	require.Equal(t, "oss", backendType)
	require.Equal(t, configJSON, backendConfig)

	file, err := os.CreateTemp("", "nydusify-backend-config-test.json")
	require.NoError(t, err)
	defer os.RemoveAll(file.Name())

	_, err = file.WriteString(configJSON)
	require.NoError(t, err)
	file.Sync()

	flagSet = flag.NewFlagSet("test4", flag.PanicOnError)
	flagSet.String("prefixbackend-type", "oss", "")
	flagSet.String("prefixbackend-config-file", file.Name(), "")
	ctx = cli.NewContext(app, flagSet, nil)
	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.NoError(t, err)
	require.Equal(t, "oss", backendType)
	require.Equal(t, configJSON, backendConfig)

	flagSet = flag.NewFlagSet("test5", flag.PanicOnError)
	flagSet.String("prefixbackend-type", "oss", "")
	flagSet.String("prefixbackend-config", configJSON, "")
	flagSet.String("prefixbackend-config-file", file.Name(), "")
	ctx = cli.NewContext(app, flagSet, nil)
	backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--backend-config conflicts with --backend-config-file")
	require.Empty(t, backendType)
	require.Empty(t, backendConfig)
}

func TestGetTargetReference(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "target",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "target-suffix",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "source",
				Value: "",
			},
		},
	}
	ctx := cli.NewContext(app, nil, nil)

	target, err := getTargetReference(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--target or --target-suffix is required")
	require.Empty(t, target)

	flagSet := flag.NewFlagSet("test1", flag.PanicOnError)
	flagSet.String("target", "testTarget", "")
	flagSet.String("target-suffix", "testSuffix", "")
	ctx = cli.NewContext(app, flagSet, nil)
	target, err = getTargetReference(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "-target conflicts with --target-suffix")
	require.Empty(t, target)

	flagSet = flag.NewFlagSet("test2", flag.PanicOnError)
	flagSet.String("target-suffix", "-nydus", "")
	flagSet.String("source", "localhost:5000/nginx:latest", "")
	ctx = cli.NewContext(app, flagSet, nil)
	target, err = getTargetReference(ctx)
	require.NoError(t, err)
	require.Equal(t, "localhost:5000/nginx:latest-nydus", target)

	flagSet = flag.NewFlagSet("test3", flag.PanicOnError)
	flagSet.String("target-suffix", "-nydus", "")
	flagSet.String("source", "localhost:5000\nginx:latest", "")
	ctx = cli.NewContext(app, flagSet, nil)
	target, err = getTargetReference(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid source image reference")
	require.Empty(t, target)

	flagSet = flag.NewFlagSet("test4", flag.PanicOnError)
	flagSet.String("target", "testTarget", "")
	ctx = cli.NewContext(app, flagSet, nil)
	target, err = getTargetReference(ctx)
	require.NoError(t, err)
	require.Equal(t, "testTarget", target)
}

func TestGetCacheReference(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "build-cache",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "build-cache-tag",
				Value: "",
			},
		},
	}
	ctx := cli.NewContext(app, nil, nil)

	cache, err := getCacheReference(ctx, "")
	require.NoError(t, err)
	require.Empty(t, cache)

	flagSet := flag.NewFlagSet("test1", flag.PanicOnError)
	flagSet.String("build-cache", "cache", "")
	flagSet.String("build-cache-tag", "cacheTag", "")
	ctx = cli.NewContext(app, flagSet, nil)
	cache, err = getCacheReference(ctx, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "--build-cache conflicts with --build-cache-tag")
	require.Empty(t, cache)

	flagSet = flag.NewFlagSet("test2", flag.PanicOnError)
	flagSet.String("build-cache-tag", "cacheTag", "errTarget")
	ctx = cli.NewContext(app, flagSet, nil)
	cache, err = getCacheReference(ctx, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid target image reference: invalid reference format")
	require.Empty(t, cache)

	flagSet = flag.NewFlagSet("test2", flag.PanicOnError)
	flagSet.String("build-cache-tag", "latest-cache", "")
	ctx = cli.NewContext(app, flagSet, nil)
	cache, err = getCacheReference(ctx, "localhost:5000/nginx:latest")
	require.NoError(t, err)
	require.Equal(t, "localhost:5000/nginx:latest-cache", cache)
}

func TestGetPrefetchPatterns(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "prefetch-dir",
				Value: "",
			},
			&cli.BoolFlag{
				Name:  "prefetch-patterns",
				Value: false,
			},
		},
	}
	ctx := cli.NewContext(app, nil, nil)

	patterns, err := getPrefetchPatterns(ctx)
	require.NoError(t, err)
	require.Equal(t, "/", patterns)

	flagSet := flag.NewFlagSet("test1", flag.PanicOnError)
	flagSet.String("prefetch-dir", "/etc/passwd", "")
	ctx = cli.NewContext(app, flagSet, nil)
	patterns, err = getPrefetchPatterns(ctx)
	require.NoError(t, err)
	require.Equal(t, "/etc/passwd", patterns)

	flagSet = flag.NewFlagSet("test2", flag.PanicOnError)
	flagSet.String("prefetch-dir", "/etc/passwd", "")
	flagSet.Bool("prefetch-patterns", true, "")
	ctx = cli.NewContext(app, flagSet, nil)
	patterns, err = getPrefetchPatterns(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--prefetch-dir conflicts with --prefetch-patterns")
	require.Empty(t, patterns)

	flagSet = flag.NewFlagSet("test3", flag.PanicOnError)
	flagSet.Bool("prefetch-patterns", true, "")
	ctx = cli.NewContext(app, flagSet, nil)
	patterns, err = getPrefetchPatterns(ctx)
	require.NoError(t, err)
	require.Equal(t, "/", patterns)
}
