// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The Nydusify CLI tool converts an OCI container image from source registry into
// a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to
// target registry.
package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"contrib/nydusify/converter"
)

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	app := &cli.App{
		Name:  "Nydusify",
		Usage: "Nydus image converter tool",
	}

	app.Commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert source image to nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "source", Required: true, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: true, Usage: "Target image reference", EnvVars: []string{"TARGET"}},

				&cli.BoolFlag{Name: "source-insecure", Required: false, Usage: "Allow http/insecure source registry communication", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Required: false, Usage: "Allow http/insecure target registry communication", EnvVars: []string{"TARGET_INSECURE"}},

				&cli.StringFlag{Name: "work-dir", Value: "./tmp", Usage: "Work directory path for image conversion", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "prefetch-dir", Value: "/", Usage: "Prefetch directory for nydus image, use absolute path of rootfs", EnvVars: []string{"PREFETCH_DIR"}},
				&cli.StringFlag{Name: "nydus-image", Value: "./nydus-image", Usage: "The nydus-image binary path", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.StringFlag{Name: "signature-key", Value: "", Usage: "Private key path for image signature", EnvVars: []string{"SIGNATURE_KEY"}},
				&cli.BoolFlag{Name: "multi-platform", Value: false, Usage: "Add manifest index (multiple platforms, OCI & Nydus) for target image", EnvVars: []string{"MULTI-PLATFORM"}},
				&cli.BoolFlag{Name: "silent", Value: false, Usage: "Disable to show conversion progress", EnvVars: []string{"SILENT"}},
			},
			Action: func(c *cli.Context) error {
				converter, err := converter.New(converter.Option{
					Source:         c.String("source"),
					Target:         c.String("target"),
					SourceInsecure: c.Bool("source-insecure"),
					TargetInsecure: c.Bool("target-insecure"),

					WorkDir:          c.String("work-dir"),
					PrefetchDir:      c.String("prefetch-dir"),
					NydusImagePath:   c.String("nydus-image"),
					SignatureKeyPath: c.String("signature-key"),
					MultiPlatform:    c.Bool("multi-platform"),
					Silent:           c.Bool("silent"),
				})
				if err != nil {
					return err
				}

				return converter.Convert()
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
