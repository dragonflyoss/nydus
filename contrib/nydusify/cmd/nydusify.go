// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The Nydusify CLI tool converts an OCI container image from source registry into
// a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to
// target registry.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/containerd/containerd/reference/docker"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"contrib/nydusify/checker"
	"contrib/nydusify/converter"
)

var versionGitCommit string
var versionBuildTime string

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

	fmt.Printf("Version: %s\n", version)

	app.Commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert source image to nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "source", Required: true, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: false, Usage: "Target (Nydus) image reference", EnvVars: []string{"TARGET"}},
				&cli.StringFlag{Name: "target-suffix", Required: false, Usage: "Add suffix to source image reference as target image reference", EnvVars: []string{"TARGET_SUFFIX"}},

				&cli.BoolFlag{Name: "source-insecure", Required: false, Usage: "Allow http/insecure source registry communication", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Required: false, Usage: "Allow http/insecure target registry communication", EnvVars: []string{"TARGET_INSECURE"}},

				&cli.StringFlag{Name: "work-dir", Value: "./tmp", Usage: "Work directory path for image conversion", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "prefetch-dir", Value: "/", Usage: "Prefetch directory for nydus image, use absolute path of rootfs", EnvVars: []string{"PREFETCH_DIR"}},
				&cli.StringFlag{Name: "nydus-image", Value: "./nydus-image", Usage: "The nydus-image binary path", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.BoolFlag{Name: "multi-platform", Value: false, Usage: "Add manifest index (multiple platforms, OCI & Nydus) for target image", EnvVars: []string{"MULTI_PLATFORM"}},
				&cli.BoolFlag{Name: "docker-v2-format", Value: false, Usage: "Use docker image manifest v2, schema 2 format", EnvVars: []string{"DOCKER_V2_FORMAT"}},
				&cli.StringFlag{Name: "backend-type", Value: "registry", Usage: "Specify Nydus blob storage backend type", EnvVars: []string{"BACKEND_TYPE"}},
				&cli.StringFlag{Name: "backend-config", Value: "", Usage: "Specify Nydus blob storage backend in JSON config string", EnvVars: []string{"BACKEND_CONFIG"}},
				&cli.StringFlag{Name: "backend-config-file", Value: "", TakesFile: true, Usage: "Specify Nydus blob storage backend config from path", EnvVars: []string{"BACKEND_CONFIG_FILE"}},
				&cli.StringFlag{Name: "build-cache", Value: "", Usage: "An remote image reference for accelerating nydus image build", EnvVars: []string{"BUILD_CACHE"}},
				&cli.BoolFlag{Name: "build-cache-insecure", Required: false, Usage: "Allow http/insecure registry communication of cache image", EnvVars: []string{"BUILD_CACHE_INSECURE"}},
				&cli.UintFlag{Name: "build-cache-max-records", Value: 200, Usage: "Maximum cache records in cache image", EnvVars: []string{"BUILD_CACHE_MAX_RECORDS"}},
			},
			Action: func(c *cli.Context) error {
				source := c.String("source")
				target := c.String("target")
				targetSuffix := c.String("target-suffix")
				if target != "" && targetSuffix != "" {
					return fmt.Errorf("--target conflicts with --target-suffix")
				}
				if target == "" && targetSuffix == "" {
					return fmt.Errorf("--target or --target-suffix is required")
				}
				// Add suffix to source image reference as the target
				// image reference, like this:
				// Source: localhost:5000/nginx:latest
				// Target: localhost:5000/nginx:latest-suffix
				if targetSuffix != "" {
					named, err := docker.ParseDockerRef(source)
					if err != nil {
						return fmt.Errorf("Invalid source image reference: %s", err)
					}
					if _, ok := named.(docker.Digested); ok {
						return fmt.Errorf("Unsupported digested image reference: %s", named.String())
					}
					named = docker.TagNameOnly(named)
					target = named.String() + targetSuffix
				}

				backendType := c.String("backend-type")
				possibleBackendTypes := []string{"registry", "oss"}
				if !isPossibleValue(possibleBackendTypes, backendType) {
					return fmt.Errorf("--backend-type should be one of %v", possibleBackendTypes)
				}
				backendConfig, err := parseBackendConfig(c.String("backend-config"), c.String("backend-config-file"))
				if err != nil {
					return err
				}
				if backendType != "registry" && strings.TrimSpace(backendConfig) == "" {
					return fmt.Errorf("--backend-config or --backend-config-file required")
				}

				buildCacheMaxRecords := c.Uint("build-cache-max-records")
				if buildCacheMaxRecords < 1 {
					return fmt.Errorf("--build-cache-max-records should be greater than 0")
				}

				converter, err := converter.New(converter.Option{
					Source:         source,
					Target:         target,
					SourceInsecure: c.Bool("source-insecure"),
					TargetInsecure: c.Bool("target-insecure"),

					WorkDir:              c.String("work-dir"),
					PrefetchDir:          c.String("prefetch-dir"),
					NydusImagePath:       c.String("nydus-image"),
					MultiPlatform:        c.Bool("multi-platform"),
					DockerV2Format:       c.Bool("docker-v2-format"),
					BackendType:          backendType,
					BackendConfig:        backendConfig,
					BuildCache:           c.String("build-cache"),
					BuildCacheInsecure:   c.Bool("build-cache-insecure"),
					BuildCacheMaxRecords: c.Uint("build-cache-max-records"),
				})
				if err != nil {
					return err
				}

				return converter.Convert()
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

				checker, err := checker.New(checker.Opt{
					WorkDir:        c.String("work-dir"),
					Source:         c.String("source"),
					Target:         c.String("target"),
					SourceInsecure: c.Bool("source-insecure"),
					TargetInsecure: c.Bool("target-insecure"),
					NydusImagePath: c.String("nydus-image"),
					NydusdPath:     c.String("nydusd"),
					BackendType:    backendType,
					BackendConfig:  backendConfig,
				})
				if err != nil {
					return err
				}

				return checker.Check()
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
