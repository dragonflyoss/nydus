// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The Nydusify CLI tool converts an OCI container image from source registry into
// a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to
// target registry.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containerd/containerd/reference/docker"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/metrics"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/metrics/fileexporter"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/packer"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/viewer"
)

var versionGitCommit string
var versionBuildTime string
var maxCacheMaxRecords uint = 50

const defaultLogLevel = logrus.InfoLevel

func isPossibleValue(excepted []string, value string) bool {
	for _, v := range excepted {
		if value == v {
			return true
		}
	}
	return false
}

func parseBackendConfig(backendConfigJSON, backendConfigFile string) (string, error) {
	if backendConfigJSON != "" && backendConfigFile != "" {
		return "", fmt.Errorf("--backend-config conflicts with --backend-config-file")
	}

	if backendConfigFile != "" {
		_backendConfigJSON, err := ioutil.ReadFile(backendConfigFile)
		if err != nil {
			return "", errors.Wrap(err, "parse backend config file")
		}
		backendConfigJSON = string(_backendConfigJSON)
	}

	return backendConfigJSON, nil
}

func getBackendConfig(c *cli.Context, required bool) (string, string, error) {
	backendType := c.String("backend-type")
	if backendType == "" {
		if required {
			return "", "", errors.Errorf("backend type is empty, please specify option '--backend-type'")
		}
		return "", "", nil
	}

	backendConfig, err := parseBackendConfig(
		c.String("backend-config"), c.String("backend-config-file"),
	)
	if err != nil {
		return "", "", err
	} else if backendConfig == "" && backendType == "oss" {
		return "", "", errors.Errorf("backend configuration is empty, please specify option '--backend-config'")
	}

	return backendType, backendConfig, nil
}

// Add suffix to source image reference as the target
// image reference, like this:
// Source: localhost:5000/nginx:latest
// Target: localhost:5000/nginx:latest-suffix
func addReferenceSuffix(source, suffix string) (string, error) {
	named, err := docker.ParseDockerRef(source)
	if err != nil {
		return "", fmt.Errorf("invalid source image reference: %s", err)
	}
	if _, ok := named.(docker.Digested); ok {
		return "", fmt.Errorf("unsupported digested image reference: %s", named.String())
	}
	named = docker.TagNameOnly(named)
	target := named.String() + suffix
	return target, nil
}

func getTargetReference(c *cli.Context) (string, error) {
	target := c.String("target")
	targetSuffix := c.String("target-suffix")
	if target != "" && targetSuffix != "" {
		return "", fmt.Errorf("--target conflicts with --target-suffix")
	}
	if target == "" && targetSuffix == "" {
		return "", fmt.Errorf("--target or --target-suffix is required")
	}
	var err error
	if targetSuffix != "" {
		target, err = addReferenceSuffix(c.String("source"), targetSuffix)
		if err != nil {
			return "", err
		}
	}
	return target, nil
}

func getCacheReference(c *cli.Context, target string) (string, error) {
	cache := c.String("build-cache")
	cacheTag := c.String("build-cache-tag")
	if cache != "" && cacheTag != "" {
		return "", fmt.Errorf("--build-cache conflicts with --build-cache-tag")
	}
	if cacheTag != "" {
		named, err := docker.ParseDockerRef(target)
		if err != nil {
			return "", fmt.Errorf("invalid target image reference: %s", err)
		}
		cache = fmt.Sprintf("%s/%s:%s", docker.Domain(named), docker.Path(named), cacheTag)
	}
	return cache, nil
}

func getPrefetchPatterns(c *cli.Context) (string, error) {
	prefetchedDir := c.String("prefetch-dir")
	prefetchPatterns := c.Bool("prefetch-patterns")

	if len(prefetchedDir) > 0 && prefetchPatterns {
		return "", fmt.Errorf("--prefetch-dir conflicts with --prefetch-patterns")
	}

	var patterns string

	if prefetchPatterns {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", errors.Wrap(err, "read prefetch patterns from STDIN")
		}
		patterns = string(bytes)
	}

	if len(prefetchedDir) > 0 {
		patterns = prefetchedDir
	}

	if len(patterns) <= 0 {
		patterns = "/"
	}

	return patterns, nil
}

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	version := fmt.Sprintf("%s.%s", versionGitCommit, versionBuildTime)

	app := &cli.App{
		Name:    "Nydusify",
		Usage:   "Nydus image converter tool",
		Version: version,
	}

	// global options
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "log-level",
			Aliases: []string{"l"},
			Value:   "info",
			Usage:   "Set log level (panic, fatal, error, warn, info, debug, trace)",
			EnvVars: []string{"LOG_LEVEL"},
		},
		&cli.BoolFlag{
			Name:     "debug",
			Aliases:  []string{"D"},
			Required: false,
			Value:    false,
			Usage:    "Enable debug log level(will overwrite `log-level` option)",
			EnvVars:  []string{"DEBUG_LOG_LEVEL"}},
	}

	logrus.Infof("Version: %s\n", version)

	app.Commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert source image to nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "source", Required: true, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: false, Usage: "Target (Nydus) image reference", EnvVars: []string{"TARGET"}},
				&cli.StringFlag{Name: "target-suffix", Required: false, Usage: "Add suffix to source image reference as target image reference, conflict with --target", EnvVars: []string{"TARGET_SUFFIX"}},
				&cli.BoolFlag{Name: "source-insecure", Required: false, Usage: "Skip verifying server certs for HTTPS source registry", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Required: false, Usage: "Skip verifying server certs for HTTPS target registry", EnvVars: []string{"TARGET_INSECURE"}},
				&cli.StringFlag{Name: "work-dir", Value: "./tmp", Usage: "Work directory path for image conversion", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "prefetch-dir", Value: "", Usage: "Prefetched directory for nydus image, use absolute path of rootfs", EnvVars: []string{"PREFETCH_DIR"}},
				&cli.BoolFlag{Name: "prefetch-patterns", Value: false, Usage: "Prefetched file path patterns from STDIN, specify absolute/relative path of rootfs line by line", EnvVars: []string{"PREFETCH_PATTERNS"}},
				&cli.StringFlag{Name: "nydus-image", Value: "nydus-image", Usage: "The nydus-image binary path, if unset, search in PATH environment", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.BoolFlag{Name: "multi-platform", Value: false, Usage: "Merge OCI & Nydus manifest to manifest index for target image, please ensure that OCI manifest already exists in target image", EnvVars: []string{"MULTI_PLATFORM"}},
				&cli.StringFlag{Name: "platform", Value: "linux/" + runtime.GOARCH, Usage: "Let nydusify choose image of specified platform from manifest index. Possible value is `linux/amd64` or `linux/arm64`"},
				&cli.BoolFlag{Name: "docker-v2-format", Value: false, Usage: "Use docker image manifest v2, schema 2 format", EnvVars: []string{"DOCKER_V2_FORMAT"}},
				&cli.StringFlag{Name: "backend-type", Value: "registry", Usage: "Specify Nydus blob storage backend type", EnvVars: []string{"BACKEND_TYPE"}},
				&cli.StringFlag{Name: "backend-config", Value: "", Usage: "Specify Nydus blob storage backend in JSON config string", EnvVars: []string{"BACKEND_CONFIG"}},
				&cli.StringFlag{Name: "backend-config-file", Value: "", TakesFile: true, Usage: "Specify Nydus blob storage backend config from path", EnvVars: []string{"BACKEND_CONFIG_FILE"}},
				&cli.BoolFlag{Name: "backend-force-push", Value: false, Usage: "Force to push Nydus blob to storage backend, even if the blob already exists in storage backend", EnvVars: []string{"BACKEND_FORCE_PUSH"}},
				&cli.BoolFlag{Name: "backend-aligned-chunk", Value: false, Usage: "Produce 4096 aligned decompressed_offset in Nydus bootstrap", EnvVars: []string{"BACKEND_ALIGNED_CHUNK"}},
				&cli.StringFlag{Name: "build-cache", Value: "", Usage: "An remote image reference for accelerating nydus image build", EnvVars: []string{"BUILD_CACHE"}},
				&cli.StringFlag{Name: "build-cache-tag", Value: "", Usage: "Use $target:$build-cache-tag as cache image reference, conflict with --build-cache", EnvVars: []string{"BUILD_CACHE_TAG"}},
				&cli.StringFlag{Name: "build-cache-version", Value: "v1", Usage: "Specify the version of cache image, if the existed remote cache image does not match the version, cache records will be dropped", EnvVars: []string{"BUILD_CACHE_VERSION"}},
				&cli.BoolFlag{Name: "build-cache-insecure", Required: false, Usage: "Allow http/insecure registry communication of cache image", EnvVars: []string{"BUILD_CACHE_INSECURE"}},
				&cli.StringFlag{Name: "chunk-dict", Required: false, Usage: "Specify a chunk dict expression for image chunk deduplication, " +
					"for examples: bootstrap:registry:localhost:5000/namespace/app:chunk_dict, bootstrap:local:/path/to/chunk_dict.boot", EnvVars: []string{"CHUNK_DICT"}},
				&cli.BoolFlag{Name: "chunk-dict-insecure", Required: false, Value: false, Usage: "Allow http/insecure registry communication of chunk dict", EnvVars: []string{"CHUNK_DICT_INSECURE"}},
				// The --build-cache-max-records flag represents the maximum number
				// of layers in cache image. 50 (bootstrap + blob in one record) was
				// chosen to make it compatible with the 127 max in graph driver of
				// docker so that we can pull cache image using docker.
				&cli.UintFlag{Name: "build-cache-max-records", Value: maxCacheMaxRecords, Usage: "Maximum cache records in cache image", EnvVars: []string{"BUILD_CACHE_MAX_RECORDS"}},
				&cli.StringFlag{Name: "fs-version", Required: false, Usage: "Version number of nydus image format, possible values: 5, 6", EnvVars: []string{"FS_VERSION"}, Value: "5", DefaultText: "V5 format"},
			},
			Action: func(c *cli.Context) error {
				setupLogLevel(c)

				target, err := getTargetReference(c)
				if err != nil {
					return err
				}

				backendType := c.String("backend-type")
				possibleBackendTypes := []string{"registry", "oss"}
				if !isPossibleValue(possibleBackendTypes, backendType) {
					return fmt.Errorf("--backend-type should be one of %v", possibleBackendTypes)
				}

				fsVersion := c.String("fs-version")
				possibleFsVersions := []string{"5", "6"}
				if !isPossibleValue(possibleFsVersions, fsVersion) {
					return fmt.Errorf("--fs-version should be one of %v", possibleFsVersions)
				}

				// This only works for OSS backend rightnow
				backendConfig, err := parseBackendConfig(c.String("backend-config"), c.String("backend-config-file"))
				if err != nil {
					return err
				}
				if backendType != "registry" && strings.TrimSpace(backendConfig) == "" {
					return fmt.Errorf("--backend-config or --backend-config-file required")
				}

				var cacheRemote *remote.Remote
				cache, err := getCacheReference(c, target)
				if err != nil {
					return err
				}
				if cache != "" {
					cacheRemote, err = provider.DefaultRemote(cache, c.Bool("build-cache-insecure"))
					if err != nil {
						return err
					}
				}

				cacheMaxRecords := c.Uint("build-cache-max-records")
				if cacheMaxRecords < 1 {
					return fmt.Errorf("--build-cache-max-records should be greater than 0")
				}
				if cacheMaxRecords > maxCacheMaxRecords {
					return fmt.Errorf("--build-cache-max-records should not be greater than %d", maxCacheMaxRecords)
				}
				cacheVersion := c.String("build-cache-version")

				logger, err := provider.DefaultLogger()
				if err != nil {
					return err
				}

				sourceRemote, err := provider.DefaultRemote(c.String("source"), c.Bool("source-insecure"))
				if err != nil {
					return errors.Wrap(err, "Parse source reference")
				}
				targetPlatform := c.String("platform")

				targetRemote, err := provider.DefaultRemote(target, c.Bool("target-insecure"))
				if err != nil {
					return err
				}

				prefetchPatterns, err := getPrefetchPatterns(c)
				if err != nil {
					return err
				}

				metrics.Register(fileexporter.New(filepath.Join(c.String("work-dir"), "conversion_metrics.prom")))
				defer metrics.Export()

				opt := converter.Opt{
					Logger: logger,

					TargetPlatform: targetPlatform,

					SourceRemote: sourceRemote,
					TargetRemote: targetRemote,

					CacheRemote:     cacheRemote,
					CacheMaxRecords: cacheMaxRecords,
					CacheVersion:    cacheVersion,

					WorkDir:          c.String("work-dir"),
					PrefetchPatterns: prefetchPatterns,
					NydusImagePath:   c.String("nydus-image"),
					MultiPlatform:    c.Bool("multi-platform"),
					DockerV2Format:   c.Bool("docker-v2-format"),

					BackendType:         backendType,
					BackendConfig:       backendConfig,
					BackendForcePush:    c.Bool("backend-force-push"),
					BackendAlignedChunk: c.Bool("backend-aligned-chunk"),

					NydusifyVersion: version,
					FsVersion:       fsVersion,

					ChunkDict: converter.ChunkDictOpt{
						Args:     c.String("chunk-dict"),
						Insecure: c.Bool("chunk-dict-insecure"),
						Platform: targetPlatform,
					},
				}

				cvt, err := converter.New(opt)
				if err != nil {
					return err
				}

				return cvt.Convert(context.Background())
			},
		},
		{
			Name:  "check",
			Usage: "Verify nydus image format and content",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "source",
					Required: false,
					Usage:    "Source image reference",
					EnvVars:  []string{"SOURCE"},
				},
				&cli.StringFlag{
					Name:     "target",
					Required: true,
					Usage:    "Target (Nydus) image reference",
					EnvVars:  []string{"TARGET"},
				},
				&cli.BoolFlag{
					Name:     "source-insecure",
					Required: false,
					Usage:    "Allow http/insecure network communication",
					EnvVars:  []string{"SOURCE_INSECURE"},
				},
				&cli.BoolFlag{
					Name:     "target-insecure",
					Required: false,
					Usage:    "Allow http/insecure network communication",
					EnvVars:  []string{"TARGET_INSECURE"},
				},

				&cli.StringFlag{
					Name:    "backend-type",
					Value:   "",
					Usage:   "Type of storage backend, enable verification of file data in Nydus image if specified",
					EnvVars: []string{"BACKEND_TYPE"},
				},
				&cli.StringFlag{
					Name:    "backend-config",
					Value:   "",
					Usage:   "Json string for storage backend configuration",
					EnvVars: []string{"BACKEND_CONFIG"},
				},
				&cli.PathFlag{
					Name:      "backend-config-file",
					Value:     "",
					TakesFile: true,
					Usage:     "Json configuration file for storage backend",
					EnvVars:   []string{"BACKEND_CONFIG_FILE"},
				},

				&cli.BoolFlag{
					Name:    "multi-platform",
					Value:   false,
					Usage:   "Verify that the image contains an image index with both OCI and Nydus manifests",
					EnvVars: []string{"MULTI_PLATFORM"},
				},
				&cli.StringFlag{
					Name:  "platform",
					Value: "linux/" + runtime.GOARCH,
					Usage: "Specify platform identifier to choose image manifest, possible values: 'linux/amd64' and 'linux/arm64'",
				},

				&cli.StringFlag{
					Name:    "work-dir",
					Value:   "./output",
					Usage:   "Working directory for image verification",
					EnvVars: []string{"WORK_DIR"},
				},
				&cli.StringFlag{
					Name:    "nydus-image",
					Value:   "nydus-image",
					Usage:   "Path to the nydus-image binary, default to search in PATH",
					EnvVars: []string{"NYDUS_IMAGE"},
				},
				&cli.StringFlag{
					Name:    "nydusd",
					Value:   "nydusd",
					Usage:   "Path to the nydusd binary, default to search in PATH",
					EnvVars: []string{"NYDUSD"},
				},
			},
			Action: func(c *cli.Context) error {
				setupLogLevel(c)

				backendType, backendConfig, err := getBackendConfig(c, false)
				if err != nil {
					return err
				}

				_, arch, err := provider.ExtractOsArch(c.String("platform"))
				if err != nil {
					return err
				}

				checker, err := checker.New(checker.Opt{
					WorkDir:        c.String("work-dir"),
					Source:         c.String("source"),
					Target:         c.String("target"),
					MultiPlatform:  c.Bool("multi-platform"),
					SourceInsecure: c.Bool("source-insecure"),
					TargetInsecure: c.Bool("target-insecure"),
					NydusImagePath: c.String("nydus-image"),
					NydusdPath:     c.String("nydusd"),
					BackendType:    backendType,
					BackendConfig:  backendConfig,
					ExpectedArch:   arch,
				})
				if err != nil {
					return err
				}

				return checker.Check(context.Background())
			},
		},
		{
			Name:    "mount",
			Aliases: []string{"view"},
			Usage:   "Mount the nydus image as a filesystem",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "target",
					Required: true,
					Usage:    "Target (Nydus) image reference",
					EnvVars:  []string{"TARGET"},
				},
				&cli.BoolFlag{
					Name:     "target-insecure",
					Required: false,
					Usage:    "Allow http/insecure network communication",
					EnvVars:  []string{"TARGET_INSECURE"},
				},

				&cli.StringFlag{
					Name:     "backend-type",
					Value:    "",
					Required: true,
					Usage:    "Type of storage backend, possible values: 'registry', 'oss'",
					EnvVars:  []string{"BACKEND_TYPE"},
				},
				&cli.StringFlag{
					Name:    "backend-config",
					Value:   "",
					Usage:   "Json configuration string for storage backend",
					EnvVars: []string{"BACKEND_CONFIG"},
				},
				&cli.PathFlag{
					Name:      "backend-config-file",
					Value:     "",
					TakesFile: true,
					Usage:     "Json configuration file for storage backend",
					EnvVars:   []string{"BACKEND_CONFIG_FILE"},
				},

				&cli.StringFlag{
					Name:    "mount-path",
					Value:   "./image-fs",
					Usage:   "Path to mount the image",
					EnvVars: []string{"MOUNT_PATH"},
				},
				&cli.StringFlag{
					Name:  "platform",
					Value: "linux/" + runtime.GOARCH,
					Usage: "Specify platform identifier to choose image manifest, possible values: 'linux/amd64' and 'linux/arm64'",
				},

				&cli.StringFlag{
					Name:    "work-dir",
					Value:   "./tmp",
					Usage:   "Working directory for image view, will be cleaned up after viewing",
					EnvVars: []string{"WORK_DIR"},
				},
				&cli.StringFlag{
					Name:    "nydusd",
					Value:   "nydusd",
					Usage:   "The nydusd binary path, if unset, search in PATH environment",
					EnvVars: []string{"NYDUSD"},
				},
			},
			Action: func(c *cli.Context) error {
				setupLogLevel(c)

				backendType, backendConfig, err := getBackendConfig(c, true)
				if err != nil {
					return err
				} else if backendConfig == "" {
					// TODO get auth from docker configuration file
					return errors.Errorf("backend configuration is empty, please specify option '--backend-config'")
				}

				_, arch, err := provider.ExtractOsArch(c.String("platform"))
				if err != nil {
					return err
				}

				fsViewer, err := viewer.New(viewer.Opt{
					WorkDir:        c.String("work-dir"),
					Target:         c.String("target"),
					TargetInsecure: c.Bool("target-insecure"),
					MountPath:      c.String("mount-path"),
					NydusdPath:     c.String("nydusd"),
					BackendType:    backendType,
					BackendConfig:  backendConfig,
					ExpectedArch:   arch,
				})
				if err != nil {
					return err
				}

				return fsViewer.View(context.Background())
			},
		},
		{
			Name:    "build",
			Aliases: []string{"pack"},
			Usage:   "Build a Nydus filesystem from a source directory",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "source-dir",
					Aliases:  []string{"target-dir"}, // for compatibility
					Required: true,
					Usage:    "Source directory to build Nydus filesystem from",
					EnvVars:  []string{"SOURCE_DIR"},
				},
				&cli.StringFlag{
					Name:     "output-dir",
					Aliases:  []string{"o"},
					Required: false,
					Usage:    "Output directory for built artifacts",
					EnvVars:  []string{"OUTPUT_DIR"},
				},
				&cli.StringFlag{
					Name:     "name",
					Aliases:  []string{"meta", "bootstrap"}, // for compatibility
					Required: true,
					Usage:    "Image name, which will be used as suffix for the generated Nydus image bootstrap/data blobs",
					EnvVars:  []string{"BOOTSTRAP", "IMAGE_NAME"},
				},

				&cli.BoolFlag{
					Name:    "backend-push",
					Value:   false,
					Usage:   "Push generated Nydus filesystem to storage backend",
					EnvVars: []string{"BACKEND_PUSH"},
				},
				&cli.StringFlag{
					Name:        "backend-type",
					Value:       "oss",
					DefaultText: "oss",
					Usage:       "Type of storage backend, possible values: 'registry', 'oss'",
					EnvVars:     []string{"BACKEND_TYPE"},
				},
				&cli.StringFlag{
					Name:    "backend-config",
					Value:   "",
					Usage:   "Json configuration string for storage backend",
					EnvVars: []string{"BACKEND_CONFIG"},
				},
				&cli.PathFlag{
					Name:      "backend-config-file",
					TakesFile: true,
					Usage:     "Json configuration file for storage backend",
					EnvVars:   []string{"BACKEND_CONFIG_FILE"},
				},

				&cli.StringFlag{
					Name:    "chunk-dict",
					Usage:   "Specify a chunk dict expression for chunk deduplication, for example: bootstrap=/path/to/dict.boot",
					EnvVars: []string{"CHUNK_DICT"},
				},
				&cli.StringFlag{
					Name:    "parent-bootstrap",
					Usage:   "Specify a parent metadata to reference data chunks",
					EnvVars: []string{"PARENT_BOOTSTRAP"},
				},
				&cli.BoolFlag{
					Name:    "compact",
					Usage:   "Compact parent bootstrap before building the image when needed",
					EnvVars: []string{"COMPACT"},
				},
				&cli.PathFlag{
					Name:      "compact-config-file",
					TakesFile: true,
					Usage: "Compact configuration file, default configuration is " +
						"{\"min_used_ratio\": 5, \"compact_blob_size\": 10485760, \"max_compact_size\": 104857600, " +
						"\"layers_to_compact\": 32}",
					EnvVars: []string{"COMPACT_CONFIG_FILE"},
				},

				&cli.StringFlag{
					Name:        "fs-version",
					Required:    false,
					Usage:       "Nydus image format version number, possible values: 5, 6",
					EnvVars:     []string{"FS_VERSION"},
					Value:       "5",
					DefaultText: "V5 format",
				},

				&cli.StringFlag{
					Name:    "nydus-image",
					Value:   "nydus-image",
					Usage:   "Path to the nydus-image binary, default to search in PATH",
					EnvVars: []string{"NYDUS_IMAGE"},
				},
			},
			Before: func(ctx *cli.Context) error {
				sourcePath := ctx.String("source-dir")
				fi, err := os.Stat(sourcePath)
				if err != nil {
					return errors.Wrapf(err, "failed to check source directory")
				}
				if !fi.IsDir() {
					return errors.Errorf("source path '%s' is not a directory", sourcePath)
				}
				return nil
			},
			Action: func(c *cli.Context) error {
				setupLogLevel(c)

				var (
					p             *packer.Packer
					res           packer.PackResult
					backendConfig *packer.BackendConfig
					err           error
				)

				// if backend-push is specified, we should make sure backend-config-file exists
				if c.Bool("backend-push") || c.Bool("compact") {
					_backendType, _backendConfig, err := getBackendConfig(c, true)
					if err != nil {
						return err
					} else if _backendType != "oss" {
						return errors.Errorf("only --backend-type=oss is supported")
					}
					cfg, err := packer.ParseBackendConfigString(_backendConfig)
					if err != nil {
						return errors.Errorf("failed to parse backend-config '%s', err = %v", _backendConfig, err)
					}
					backendConfig = &cfg
				}

				if p, err = packer.New(packer.Opt{
					LogLevel:       logrus.GetLevel(),
					NydusImagePath: c.String("nydus-image"),
					OutputDir:      c.String("output-dir"),
					BackendConfig:  backendConfig,
				}); err != nil {
					return err
				}

				if res, err = p.Pack(context.Background(), packer.PackRequest{
					SourceDir:    c.String("source-dir"),
					ImageName:    c.String("name"),
					PushToRemote: c.Bool("backend-push"),
					FsVersion:    c.String("fs-version"),

					ChunkDict:         c.String("chunk-dict"),
					Parent:            c.String("parent-bootstrap"),
					TryCompact:        c.Bool("compact"),
					CompactConfigPath: c.String("compact-config-file"),
				}); err != nil {
					return err
				}
				logrus.Infof("successfully built Nydus image (bootstrap:'%s', blob:'%s')", res.Meta, res.Blob)
				return nil
			},
		},
	}

	// With linux/arm64 platform, containerd/compression prioritizes `unpigz`
	// to decompress tar.gz file, which may generate corrupted data somehow.
	// Keep the same behavior with x86_64 platform by disabling pigz.
	os.Setenv("CONTAINERD_DISABLE_PIGZ", "1")

	if !utils.IsSupportedArch(runtime.GOARCH) {
		logrus.Fatal("Nydusify can only work under architecture 'amd64' and 'arm64'")
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func setupLogLevel(c *cli.Context) {
	// global `-D` has the highest priority
	if c.Bool("D") {
		logrus.SetLevel(logrus.DebugLevel)
		return
	}

	lvl := c.String("log-level")
	logLevel, err := logrus.ParseLevel(lvl)
	if err != nil {
		logrus.Warnf("failed to parse log level(%s): %+v\ndefault log level(info) will be used", lvl, err)
		logLevel = defaultLogLevel
	}

	logrus.SetLevel(logLevel)
}
