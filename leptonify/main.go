/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"os"

	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/dragonflyoss/lepton/leptonify/internal/checker"
	"github.com/dragonflyoss/lepton/leptonify/internal/converter"
	"github.com/dragonflyoss/lepton/leptonify/internal/remote"
)

func main() {
	app := &cli.App{
		Name:  "leptonify",
		Usage: "Convert OCI images to lepton images",
		Commands: []*cli.Command{
			convertCommand(),
			checkCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func convertCommand() *cli.Command {
	return &cli.Command{
		Name:  "convert",
		Usage: "Pull an OCI image, convert it to a lepton image, and push the result",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "source OCI image reference (e.g. registry/repo:tag)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "target lepton image reference to push",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the lepton binary",
				Value: "lepton",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "scratch directory for conversion (defaults to a temp dir)",
			},
			&cli.UintFlag{
				Name:  "chunk-size",
				Usage: "lepton file chunk size in bytes",
				Value: 1 << 20,
			},
			&cli.StringFlag{
				Name:  "compressor",
				Usage: "chunk data compressor: none or zstd",
				Value: "zstd",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "convert only the given platform (e.g. linux/amd64); defaults to all",
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "skip TLS certificate verification for the registry",
			},
			&cli.BoolFlag{
				Name:  "plain-http",
				Usage: "use plain HTTP to talk to the registry",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "log level: trace, debug, info, warn, error",
				Value: "info",
			},
		},
		Action: runConvert,
	}
}

func runConvert(c *cli.Context) error {
	if level, err := logrus.ParseLevel(c.String("log-level")); err == nil {
		logrus.SetLevel(level)
	}

	ctx := log.WithLogger(context.Background(), log.L)

	source := c.String("source")
	target := c.String("target")

	platformMC := platforms.All
	if p := c.String("platform"); p != "" {
		parsed, err := platforms.Parse(p)
		if err != nil {
			return errors.Wrapf(err, "invalid platform %q", p)
		}
		platformMC = platforms.Only(parsed)
	}

	// Prepare a scratch work directory.
	workDir := c.String("work-dir")
	cleanup := false
	if workDir == "" {
		tmp, err := os.MkdirTemp("", "leptonify-")
		if err != nil {
			return errors.Wrap(err, "create work dir")
		}
		workDir = tmp
		cleanup = true
	} else if err := os.MkdirAll(workDir, 0o755); err != nil {
		return errors.Wrapf(err, "create work dir %q", workDir)
	}
	if cleanup {
		defer func() { _ = os.RemoveAll(workDir) }()
	}

	contentDir := joinWork(workDir, "content")
	scratchDir := joinWork(workDir, "scratch")
	for _, d := range []string{contentDir, scratchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	provider, err := remote.NewProvider(remote.Options{
		WorkDir:    contentDir,
		Insecure:   c.Bool("insecure"),
		PlainHTTP:  c.Bool("plain-http"),
		PlatformMC: platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}

	logrus.Infof("pulling source image %s", source)
	srcDesc, err := provider.Pull(ctx, source)
	if err != nil {
		return errors.Wrapf(err, "pull %q", source)
	}

	logrus.Infof("converting image to lepton format")
	newDesc, err := converter.Convert(ctx, provider.ContentStore(), srcDesc, converter.Option{
		BuilderPath: c.String("builder"),
		WorkDir:     scratchDir,
		ChunkSize:   uint32(c.Uint("chunk-size")),
		Compressor:  c.String("compressor"),
		PlatformMC:  platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "convert")
	}

	logrus.Infof("pushing lepton image %s", target)
	if err := provider.Push(ctx, *newDesc, target); err != nil {
		return errors.Wrapf(err, "push %q", target)
	}

	logrus.Infof("done: %s -> %s (%s)", source, target, newDesc.Digest)
	return nil
}

func checkCommand() *cli.Command {
	return &cli.Command{
		Name:  "check",
		Usage: "Validate the consistency of an OCI and/or lepton image",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "source",
				Aliases: []string{"s"},
				Usage:   "source image reference (OCI or lepton); may be empty",
			},
			&cli.StringFlag{
				Name:    "target",
				Aliases: []string{"t"},
				Usage:   "target image reference (OCI or lepton); may be empty",
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the lepton binary",
				Value: "lepton",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "scratch directory for checking (defaults to a temp dir)",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "check only the given platform (e.g. linux/amd64); defaults to the host platform",
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "skip TLS certificate verification for the registry",
			},
			&cli.BoolFlag{
				Name:  "plain-http",
				Usage: "use plain HTTP to talk to the registry",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "log level: trace, debug, info, warn, error",
				Value: "info",
			},
		},
		Action: runCheck,
	}
}

func runCheck(c *cli.Context) error {
	if level, err := logrus.ParseLevel(c.String("log-level")); err == nil {
		logrus.SetLevel(level)
	}

	ctx := log.WithLogger(context.Background(), log.L)

	source := c.String("source")
	target := c.String("target")
	if source == "" && target == "" {
		return errors.New("at least one of --source or --target must be provided")
	}

	platformMC := platforms.Default()
	if p := c.String("platform"); p != "" {
		parsed, err := platforms.Parse(p)
		if err != nil {
			return errors.Wrapf(err, "invalid platform %q", p)
		}
		platformMC = platforms.Only(parsed)
	}

	// Prepare a scratch work directory.
	workDir := c.String("work-dir")
	cleanup := false
	if workDir == "" {
		tmp, err := os.MkdirTemp("", "leptonify-check-")
		if err != nil {
			return errors.Wrap(err, "create work dir")
		}
		workDir = tmp
		cleanup = true
	} else if err := os.MkdirAll(workDir, 0o755); err != nil {
		return errors.Wrapf(err, "create work dir %q", workDir)
	}
	if cleanup {
		defer func() { _ = os.RemoveAll(workDir) }()
	}

	chk, err := checker.New(checker.Opt{
		Source:     source,
		Target:     target,
		Builder:    c.String("builder"),
		WorkDir:    workDir,
		Insecure:   c.Bool("insecure"),
		PlainHTTP:  c.Bool("plain-http"),
		PlatformMC: platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create checker")
	}

	if err := chk.Check(ctx); err != nil {
		return errors.Wrap(err, "check")
	}

	logrus.Infof("check passed")
	return nil
}

func joinWork(base, sub string) string {
	return base + string(os.PathSeparator) + sub
}
