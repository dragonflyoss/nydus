// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The nydusify tool converts a remote container image into a nydus image.
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
		Name:  "Nydus image converter tool",
		Usage: "CLI",
	}

	app.Commands = []*cli.Command{
		{
			Name:  "convert",
			Usage: "Convert source image to nydus image",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "containerd-sock", Value: "/run/containerd/containerd.sock", Usage: "Containerd service sock path", EnvVars: []string{"CONTAINERD_SOCK"}},
				&cli.StringFlag{Name: "source", Required: true, Usage: "Source image reference", EnvVars: []string{"SOURCE"}},
				&cli.StringFlag{Name: "target", Required: true, Usage: "Target image reference", EnvVars: []string{"TARGET"}},
				&cli.StringFlag{Name: "source-auth", Value: "", Usage: "Base64 encoded auth string for source registry", EnvVars: []string{"SOURCE_AUTH"}},
				&cli.StringFlag{Name: "target-auth", Value: "", Usage: "Base64 encoded auth string for target registry", EnvVars: []string{"TARGET_AUTH"}},
				&cli.BoolFlag{Name: "source-insecure", Value: false, Usage: "Using http scheme for source registry", EnvVars: []string{"SOURCE_INSECURE"}},
				&cli.BoolFlag{Name: "target-insecure", Value: false, Usage: "Using http scheme for target registry", EnvVars: []string{"TARGET_INSECURE"}},

				&cli.StringFlag{Name: "work-dir", Value: "./tmp", Usage: "Work directory for image convert", EnvVars: []string{"WORK_DIR"}},
				&cli.StringFlag{Name: "prefetch-dir", Value: "/", Usage: "Prefetch directory for nydus image", EnvVars: []string{"PREFETCH_DIR"}},
				&cli.StringFlag{Name: "nydus-image", Value: "./nydus-image", Usage: "Nydus image builder binary path", EnvVars: []string{"NYDUS_IMAGE"}},
				&cli.StringFlag{Name: "signature-key", Value: "", Usage: "Private key path for image signature", EnvVars: []string{"SIGNATURE_KEY"}},
			},
			Action: func(c *cli.Context) error {
				option := converter.Option{
					ContainerdSock: c.String("containerd-sock"),
					Source:         c.String("source"),
					Target:         c.String("target"),
					SourceAuth:     c.String("source-auth"),
					TargetAuth:     c.String("target-auth"),
					SourceInsecure: c.Bool("source-insecure"),
					TargetInsecure: c.Bool("target-insecure"),

					WorkDir:          c.String("work-dir"),
					PrefetchDir:      c.String("prefetch-dir"),
					NydusImagePath:   c.String("nydus-image"),
					SignatureKeyPath: c.String("signature-key"),
				}

				if option.TargetAuth == "" {
					option.TargetAuth = option.SourceAuth
				}
				if !c.IsSet("target-insecure") {
					option.TargetInsecure = option.SourceInsecure
				}

				if err := converter.Convert(option); err != nil {
					return err
				}
				return nil
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
