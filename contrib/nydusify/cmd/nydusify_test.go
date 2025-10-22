// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
	tests := []struct {
		backendType   string
		backendConfig string
	}{
		{
			backendType: "oss",
			backendConfig: `
	{
		"bucket_name": "test",
		"endpoint": "region.oss.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"meta_prefix": "meta",
		"blob_prefix": "blob"
	}`,
		},
		{
			backendType: "localfs",
			backendConfig: `
	{
		"dir": "/path/to/blobs"
	}`,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("backend config %s", test.backendType), func(t *testing.T) {
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
			flagSet.String("prefixbackend-type", test.backendType, "")
			ctx = cli.NewContext(app, flagSet, nil)
			backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
			require.Error(t, err)
			require.Contains(t, err.Error(), "backend configuration is empty, please specify option")
			require.Empty(t, backendType)
			require.Empty(t, backendConfig)

			require.True(t, json.Valid([]byte(test.backendConfig)))

			flagSet = flag.NewFlagSet("test3", flag.PanicOnError)
			flagSet.String("prefixbackend-type", test.backendType, "")
			flagSet.String("prefixbackend-config", test.backendConfig, "")
			ctx = cli.NewContext(app, flagSet, nil)
			backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
			require.NoError(t, err)
			require.Equal(t, test.backendType, backendType)
			require.Equal(t, test.backendConfig, backendConfig)

			file, err := os.CreateTemp("", "nydusify-backend-config-test.json")
			require.NoError(t, err)
			defer os.RemoveAll(file.Name())

			_, err = file.WriteString(test.backendConfig)
			require.NoError(t, err)
			file.Sync()

			flagSet = flag.NewFlagSet("test4", flag.PanicOnError)
			flagSet.String("prefixbackend-type", test.backendType, "")
			flagSet.String("prefixbackend-config-file", file.Name(), "")
			ctx = cli.NewContext(app, flagSet, nil)
			backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
			require.NoError(t, err)
			require.Equal(t, test.backendType, backendType)
			require.Equal(t, test.backendConfig, backendConfig)

			flagSet = flag.NewFlagSet("test5", flag.PanicOnError)
			flagSet.String("prefixbackend-type", test.backendType, "")
			flagSet.String("prefixbackend-config", test.backendConfig, "")
			flagSet.String("prefixbackend-config-file", file.Name(), "")
			ctx = cli.NewContext(app, flagSet, nil)
			backendType, backendConfig, err = getBackendConfig(ctx, "prefix", true)
			require.Error(t, err)
			require.Contains(t, err.Error(), "--backend-config conflicts with --backend-config-file")
			require.Empty(t, backendType)
			require.Empty(t, backendConfig)
		})
	}
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

func TestGetGlobalFlags(t *testing.T) {
	flags := getGlobalFlags()
	require.Equal(t, 3, len(flags))
}

func TestSetupLogLevelWithLogFile(t *testing.T) {
	logFilePath := "test_log_file.log"
	defer os.Remove(logFilePath)

	c := &cli.Context{}

	patches := gomonkey.ApplyMethodSeq(c, "String", []gomonkey.OutputCell{
		{Values: []interface{}{"info"}, Times: 1},
		{Values: []interface{}{"test_log_file.log"}, Times: 2},
	})
	defer patches.Reset()
	setupLogLevel(c)

	file, err := os.Open(logFilePath)
	assert.NoError(t, err)
	assert.NotNil(t, file)
	file.Close()

	logrusOutput := logrus.StandardLogger().Out
	assert.NotNil(t, logrusOutput)

	logrus.Info("This is a test log message")
	content, err := os.ReadFile(logFilePath)
	assert.NoError(t, err)
	assert.Contains(t, string(content), "This is a test log message")
}

func TestSetupLogLevelWithInvalidLogFile(t *testing.T) {

	c := &cli.Context{}

	patches := gomonkey.ApplyMethodSeq(c, "String", []gomonkey.OutputCell{
		{Values: []interface{}{"info"}, Times: 1},
		{Values: []interface{}{"test/test_log_file.log"}, Times: 2},
	})
	defer patches.Reset()
	setupLogLevel(c)

	logrusOutput := logrus.StandardLogger().Out
	assert.NotNil(t, logrusOutput)
}

func TestValidateSourceAndTargetArchives(t *testing.T) {
	// Create temporary source archive for valid cases
	validSourceFile, err := os.CreateTemp("", "source-archive-*.tar")
	require.NoError(t, err)
	defer os.Remove(validSourceFile.Name())
	validSourceFile.Close()

	// Create temporary directory for valid target cases
	validTargetDir, err := os.MkdirTemp("", "target-dir-*")
	require.NoError(t, err)
	defer os.RemoveAll(validTargetDir)

	tests := []struct {
		name          string
		sourceArchive string
		targetArchive string
		expectError   bool
		errorContains string
	}{
		{
			name:          "no archives specified",
			sourceArchive: "",
			targetArchive: "",
			expectError:   false,
		},
		{
			name:          "valid source archive only",
			sourceArchive: validSourceFile.Name(),
			targetArchive: "",
			expectError:   false,
		},
		{
			name:          "non-existent source archive",
			sourceArchive: "/path/to/non-existent-source.tar",
			targetArchive: "",
			expectError:   true,
			errorContains: "source archive not accessible",
		},
		{
			name:          "valid target archive with existing directory",
			sourceArchive: "",
			targetArchive: fmt.Sprintf("%s/target-archive.tar", validTargetDir),
			expectError:   false,
		},
		{
			name:          "target archive with non-existent directory",
			sourceArchive: "",
			targetArchive: "/non/existent/directory/target.tar",
			expectError:   true,
			errorContains: "target archive directory not accessible",
		},
		{
			name:          "valid source and target archives",
			sourceArchive: validSourceFile.Name(),
			targetArchive: fmt.Sprintf("%s/target-archive.tar", validTargetDir),
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &cli.App{
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "source-archive",
						Value: "",
					},
					&cli.StringFlag{
						Name:  "target-archive",
						Value: "",
					},
				},
			}

			flagSet := flag.NewFlagSet("test", flag.PanicOnError)
			flagSet.String("source-archive", tt.sourceArchive, "")
			flagSet.String("target-archive", tt.targetArchive, "")
			ctx := cli.NewContext(app, flagSet, nil)

			err := validateSourceAndTargetArchives(ctx)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					require.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
