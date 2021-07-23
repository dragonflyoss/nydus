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
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

var versionGitCommit string
var versionBuildTime string
var maxCacheMaxRecords uint = 50

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

	logrus.Infof("Version: %s\n", version)

	app.Commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert source image to nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "log-level", Value: "info", Usage: "Set log level (panic, fatal, error, warn, info, debug, trace)", EnvVars: []string{"LOG_LEVEL"}},
				&cli.StringFlag{Name: "source", Required: true, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: false, Usage: "Target (Nydus) image reference", EnvVars: []string{"TARGET"}},
				&cli.StringFlag{Name: "target-suffix", Required: false, Usage: "Add suffix to source image reference as target image reference, conflict with --target", EnvVars: []string{"TARGET_SUFFIX"}},
				&cli.BoolFlag{Name: "source-insecure", Required: false, Usage: "Allow http/insecure source registry communication", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Required: false, Usage: "Allow http/insecure target registry communication", EnvVars: []string{"TARGET_INSECURE"}},
				&cli.StringFlag{Name: "work-dir", Value: "./tmp", Usage: "Work directory path for image conversion", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "prefetch-dir", Value: "/", Usage: "Prefetch directory for nydus image, use absolute path of rootfs", EnvVars: []string{"PREFETCH_DIR"}},
				&cli.StringFlag{Name: "nydus-image", Value: "./nydus-image", Usage: "The nydus-image binary path", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.BoolFlag{Name: "multi-platform", Value: false, Usage: "Merge OCI & Nydus manifest to manifest index for target image, please ensure that OCI manifest already exists in target image", EnvVars: []string{"MULTI_PLATFORM"}},
				&cli.StringFlag{Name: "platform", Value: "linux/" + runtime.GOARCH, Usage: "Let nydusify choose image of specified platform from manifest index. Possible value is `amd64` or `arm64`"},
				&cli.BoolFlag{Name: "docker-v2-format", Value: false, Usage: "Use docker image manifest v2, schema 2 format", EnvVars: []string{"DOCKER_V2_FORMAT"}},
				&cli.StringFlag{Name: "backend-type", Value: "registry", Usage: "Specify Nydus blob storage backend type", EnvVars: []string{"BACKEND_TYPE"}},
				&cli.StringFlag{Name: "backend-config", Value: "", Usage: "Specify Nydus blob storage backend in JSON config string", EnvVars: []string{"BACKEND_CONFIG"}},
				&cli.StringFlag{Name: "backend-config-file", Value: "", TakesFile: true, Usage: "Specify Nydus blob storage backend config from path", EnvVars: []string{"BACKEND_CONFIG_FILE"}},
				&cli.BoolFlag{Name: "backend-force-push", Value: false, Usage: "Force to push Nydus blob to storage backend, even if the blob already exists in storage backend", EnvVars: []string{"BACKEND_FORCE_PUSH"}},
				&cli.StringFlag{Name: "build-cache", Value: "", Usage: "An remote image reference for accelerating nydus image build", EnvVars: []string{"BUILD_CACHE"}},
				&cli.StringFlag{Name: "build-cache-tag", Value: "", Usage: "Use $target:$build-cache-tag as cache image reference, conflict with --build-cache", EnvVars: []string{"BUILD_CACHE_TAG"}},
				&cli.StringFlag{Name: "build-cache-version", Value: "v1", Usage: "Specify the version of cache image, if the existed remote cache image does not match the version, cache records will be dropped", EnvVars: []string{"BUILD_CACHE_VERSION"}},
				&cli.BoolFlag{Name: "build-cache-insecure", Required: false, Usage: "Allow http/insecure registry communication of cache image", EnvVars: []string{"BUILD_CACHE_INSECURE"}},
				// The --build-cache-max-records flag represents the maximum number
				// of layers in cache image. 50 (bootstrap + blob in one record) was
				// chosen to make it compatible with the 127 max in graph driver of
				// docker so that we can pull cache image using docker.
				&cli.UintFlag{Name: "build-cache-max-records", Value: maxCacheMaxRecords, Usage: "Maximum cache records in cache image", EnvVars: []string{"BUILD_CACHE_MAX_RECORDS"}},
			},
			Action: func(c *cli.Context) error {
				logLevel, err := logrus.ParseLevel(c.String("log-level"))
				if err != nil {
					return err
				}
				logrus.SetLevel(logLevel)

				target, err := getTargetReference(c)
				if err != nil {
					return err
				}

				backendType := c.String("backend-type")
				possibleBackendTypes := []string{"registry", "oss"}
				if !isPossibleValue(possibleBackendTypes, backendType) {
					return fmt.Errorf("--backend-type should be one of %v", possibleBackendTypes)
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

				sourceDir := filepath.Join(c.String("work-dir"), "source")
				if err := os.RemoveAll(sourceDir); err != nil {
					return err
				}
				if err := os.MkdirAll(sourceDir, 0755); err != nil {
					return err
				}
				sourceRemote, err := provider.DefaultRemote(c.String("source"), c.Bool("source-insecure"))
				if err != nil {
					return errors.Wrap(err, "Parse source reference")
				}
				targetPlatform := c.String("platform")

				sourceProviders, err := provider.DefaultSource(context.Background(), sourceRemote, sourceDir, targetPlatform)
				if err != nil {
					return errors.Wrap(err, "Parse source image")
				}

				targetRemote, err := provider.DefaultRemote(target, c.Bool("target-insecure"))
				if err != nil {
					return err
				}

				opt := converter.Opt{
					Logger:          logger,
					SourceProviders: sourceProviders,

					TargetRemote: targetRemote,

					CacheRemote:     cacheRemote,
					CacheMaxRecords: cacheMaxRecords,
					CacheVersion:    cacheVersion,

					WorkDir:        c.String("work-dir"),
					PrefetchDir:    c.String("prefetch-dir"),
					NydusImagePath: c.String("nydus-image"),
					MultiPlatform:  c.Bool("multi-platform"),
					DockerV2Format: c.Bool("docker-v2-format"),

					BackendType:      backendType,
					BackendConfig:    backendConfig,
					BackendForcePush: c.Bool("backend-force-push"),

					NydusifyVersion: version,
					Source:          c.String("source"),
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
			Usage: "Check nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "source", Required: false, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: true, Usage: "Target (Nydus) image reference", EnvVars: []string{"TARGET"}},

				&cli.BoolFlag{Name: "source-insecure", Required: false, Usage: "Allow http/insecure source registry communication", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Required: false, Usage: "Allow http/insecure target registry communication", EnvVars: []string{"TARGET_INSECURE"}},

				&cli.BoolFlag{Name: "multi-platform", Value: false, Usage: "Ensure the target image represents a manifest list, and it should consist of OCI and Nydus manifest", EnvVars: []string{"MULTI_PLATFORM"}},
				&cli.StringFlag{Name: "platform", Value: "linux/" + runtime.GOARCH, Usage: "Let nydusify choose image of specified platform from manifest index. Possible value is `amd64` or `arm64`"},
				&cli.StringFlag{Name: "work-dir", Value: "./output", Usage: "Work directory path for image check, will be cleaned before checking", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "nydus-image", Value: "./nydus-image", Usage: "The nydus-image binary path", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.StringFlag{Name: "nydusd", Value: "./nydusd", Usage: "The nydusd binary path", EnvVars: []string{"NYDUSD"}},
				&cli.StringFlag{Name: "backend-type", Value: "", Usage: "Specify Nydus blob storage backend type, will check file data in Nydus image if specified", EnvVars: []string{"BACKEND_TYPE"}},
				&cli.StringFlag{Name: "backend-config", Value: "", Usage: "Specify Nydus blob storage backend in JSON config string", EnvVars: []string{"BACKEND_CONFIG"}},
				&cli.StringFlag{Name: "backend-config-file", Value: "", TakesFile: true, Usage: "Specify Nydus blob storage backend config from path", EnvVars: []string{"BACKEND_CONFIG_FILE"}},
			},
			Action: func(c *cli.Context) error {
				backendType := c.String("backend-type")
				backendConfig := ""
				if backendType != "" {
					_backendConfig, err := parseBackendConfig(
						c.String("backend-config"), c.String("backend-config-file"),
					)
					if err != nil {
						return err
					}
					backendConfig = _backendConfig
				}

				_, arch, err := provider.ExtractOsArch(c.String("platform"))

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
	}

	// Under platform linux/arm64, containerd/compression prioritizes using `unpigz`
	// to decompress tar.giz, which will be corrupted somehow. By disabling it,
	// keep nydusify behavior the same with x86_64 platform.
	os.Setenv("CONTAINERD_DISABLE_PIGZ", "1")

	if !utils.IsSupportedArch(runtime.GOARCH) {
		logrus.Fatal("Nydusify can only work under architecture 'amd64' and 'arm64'")
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
