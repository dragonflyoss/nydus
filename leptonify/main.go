/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/dustin/go-humanize"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
			mountCommand(),
			optimizeCommand(),
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
				Usage:    "source OCI image reference (e.g. registry/repo:tag) or local directory path",
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
			&cli.UintFlag{
				Name:  "compress-size",
				Usage: "lepton group uncompressed size in bytes (must be a multiple of 1MiB)",
				Value: 4 << 20,
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
			&cli.StringSliceFlag{
				Name:  "append-in-bootstrap",
				Usage: "local file paths to bundle into the bootstrap layer alongside image.boot; files inside --source are excluded from the blob data region",
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
	appendFiles := c.StringSlice("append-in-bootstrap")

	// Detect whether --source is a local directory (instead of an OCI image
	// reference). When the source is a directory, we use ConvertLocalDir
	// which builds a single-layer lepton image directly from the directory
	// tree, excluding any --append-in-bootstrap files that reside inside it.
	isLocalDir := false
	if info, err := os.Stat(source); err == nil && info.IsDir() {
		isLocalDir = true
	}

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

	var newDesc *ocispec.Descriptor

	if isLocalDir {
		logrus.Infof("converting local directory %s to lepton format", source)
		newDesc, err = converter.ConvertLocalDir(ctx, provider.ContentStore(), converter.LocalDirOption{
			BuilderPath:       c.String("builder"),
			WorkDir:           scratchDir,
			ChunkSize:         uint32(c.Uint("chunk-size")),
			CompressSize:      uint32(c.Uint("compress-size")),
			Compressor:        c.String("compressor"),
			LogLevel:          c.String("log-level"),
			SourceDir:         source,
			AppendInBootstrap: appendFiles,
		})
		if err != nil {
			return errors.Wrap(err, "convert local directory")
		}
	} else {
		logrus.Infof("pulling source image %s", source)
		srcDesc, err := provider.Pull(ctx, source)
		if err != nil {
			return errors.Wrapf(err, "pull %q", source)
		}

		logrus.Infof("converting image to lepton format")
		newDesc, err = converter.Convert(ctx, provider.ContentStore(), srcDesc, converter.Option{
			BuilderPath:  c.String("builder"),
			WorkDir:      scratchDir,
			ChunkSize:    uint32(c.Uint("chunk-size")),
			CompressSize: uint32(c.Uint("compress-size")),
			Compressor:   c.String("compressor"),
			LogLevel:     c.String("log-level"),
			PlatformMC:   platformMC,
		})
		if err != nil {
			return errors.Wrap(err, "convert")
		}

		// Report the total layer size of both images so the conversion's size
		// impact is visible. Errors here are non-fatal.
		cs := provider.ContentStore()
		if srcSize, err := totalLayerSize(ctx, cs, srcDesc, platformMC); err != nil {
			logrus.Warnf("failed to compute source image size: %v", err)
		} else if dstSize, err := totalLayerSize(ctx, cs, *newDesc, platformMC); err != nil {
			logrus.Warnf("failed to compute target image size: %v", err)
		} else {
			logrus.Infof("image size: oci %s -> lepton %s",
				humanize.IBytes(srcSize), humanize.IBytes(dstSize))
		}
	}

	logrus.Infof("pushing lepton image %s", target)
	if err := provider.Push(ctx, *newDesc, target); err != nil {
		return errors.Wrapf(err, "push %q", target)
	}

	logrus.Infof("done: %s -> %s (%s)", source, target, newDesc.Digest)
	return nil
}

// totalLayerSize resolves rootDesc (a manifest or a multi-platform index) for
// the requested platform and returns the sum of its layer descriptor sizes.
func totalLayerSize(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (uint64, error) {
	manifestDesc, err := resolveManifest(ctx, cs, rootDesc, platformMC)
	if err != nil {
		return 0, err
	}

	var manifest ocispec.Manifest
	b, err := content.ReadBlob(ctx, cs, manifestDesc)
	if err != nil {
		return 0, errors.Wrap(err, "read manifest blob")
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return 0, errors.Wrap(err, "unmarshal manifest")
	}

	var total uint64
	for _, layer := range manifest.Layers {
		if layer.Size > 0 {
			total += uint64(layer.Size)
		}
	}
	return total, nil
}

// resolveManifest returns the platform-specific manifest descriptor, selecting
// from an index when rootDesc is multi-platform.
func resolveManifest(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (ocispec.Descriptor, error) {
	if images.IsManifestType(rootDesc.MediaType) {
		return rootDesc, nil
	}
	if !images.IsIndexType(rootDesc.MediaType) {
		return ocispec.Descriptor{}, errors.Errorf("unsupported root media type %q", rootDesc.MediaType)
	}

	var index ocispec.Index
	b, err := content.ReadBlob(ctx, cs, rootDesc)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "read index blob")
	}
	if err := json.Unmarshal(b, &index); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "unmarshal index")
	}
	for _, m := range index.Manifests {
		if m.Platform == nil || platformMC.Match(*m.Platform) {
			return m, nil
		}
	}
	return ocispec.Descriptor{}, errors.New("no manifest matches the requested platform")
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
		LogLevel:   c.String("log-level"),
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

func mountCommand() *cli.Command {
	return &cli.Command{
		Name:  "mount",
		Usage: "Mount an OCI or lepton image at a local mountpoint",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "target image reference (OCI or lepton)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "mountpoint",
				Aliases:  []string{"m"},
				Usage:    "directory to mount the image at",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the lepton binary",
				Value: "lepton",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "scratch directory for mounting (defaults to a temp dir)",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "mount only the given platform (e.g. linux/amd64); defaults to the host platform",
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Usage: "skip TLS certificate verification for the registry",
			},
			&cli.BoolFlag{
				Name:  "plain-http",
				Usage: "use plain HTTP to talk to the registry",
			},
			&cli.BoolFlag{
				Name:  "prefetch",
				Usage: "enable background blob prefetch after mounting (off by default)",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "log level: trace, debug, info, warn, error",
				Value: "info",
			},
		},
		Action: runMount,
	}
}

func runMount(c *cli.Context) error {
	if level, err := logrus.ParseLevel(c.String("log-level")); err == nil {
		logrus.SetLevel(level)
	}

	ctx := log.WithLogger(context.Background(), log.L)

	target := c.String("target")
	mountpoint := c.String("mountpoint")

	platformMC := platforms.Default()
	if p := c.String("platform"); p != "" {
		parsed, err := platforms.Parse(p)
		if err != nil {
			return errors.Wrapf(err, "invalid platform %q", p)
		}
		platformMC = platforms.Only(parsed)
	}

	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return errors.Wrapf(err, "create mountpoint %q", mountpoint)
	}

	// Prepare a scratch work directory.
	workDir := c.String("work-dir")
	cleanup := false
	if workDir == "" {
		tmp, err := os.MkdirTemp("", "leptonify-mount-")
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

	mnt, err := checker.NewMounter(checker.MountOpt{
		Target:     target,
		Mountpoint: mountpoint,
		Builder:    c.String("builder"),
		WorkDir:    workDir,
		Insecure:   c.Bool("insecure"),
		PlainHTTP:  c.Bool("plain-http"),
		Prefetch:   c.Bool("prefetch"),
		LogLevel:   c.String("log-level"),
		PlatformMC: platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create mounter")
	}

	if err := mnt.Mount(ctx); err != nil {
		return errors.Wrap(err, "mount")
	}
	return nil
}

func optimizeCommand() *cli.Command {
	return &cli.Command{
		Name:  "optimize",
		Usage: "Build an ondemand blob from a /trace access pattern and push an optimized lepton image",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "apiserver",
				Usage:    "apiserver address of a running mount of the source image (e.g. unix:///path/to/apiserver.sock); access patterns are fetched from its /trace endpoint",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "source lepton image reference",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "optimized lepton image reference to push",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the lepton binary",
				Value: "lepton",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "scratch directory for optimizing (defaults to a temp dir)",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "optimize only the given platform (e.g. linux/amd64); defaults to the host platform",
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
		Action: runOptimize,
	}
}

func runOptimize(c *cli.Context) error {
	if level, err := logrus.ParseLevel(c.String("log-level")); err == nil {
		logrus.SetLevel(level)
	}

	ctx := log.WithLogger(context.Background(), log.L)

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
		tmp, err := os.MkdirTemp("", "leptonify-optimize-")
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

	opt, err := checker.NewOptimizer(checker.OptimizeOpt{
		Source:     c.String("source"),
		Target:     c.String("target"),
		Apiserver:  c.String("apiserver"),
		Builder:    c.String("builder"),
		WorkDir:    workDir,
		Insecure:   c.Bool("insecure"),
		PlainHTTP:  c.Bool("plain-http"),
		LogLevel:   c.String("log-level"),
		PlatformMC: platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create optimizer")
	}

	if err := opt.Optimize(ctx); err != nil {
		return errors.Wrap(err, "optimize")
	}

	logrus.Infof("optimized %s -> %s", c.String("source"), c.String("target"))
	return nil
}
