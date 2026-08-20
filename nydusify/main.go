/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"os"
	"os/signal"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/dustin/go-humanize"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydusify/internal/checker"
	"github.com/dragonflyoss/nydus/nydusify/internal/mounter"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/optimizer"
	"github.com/dragonflyoss/nydus/nydusify/internal/pipeline"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
)

func main() {
	app := &cli.App{
		Name:  "nydusify",
		Usage: "Convert OCI images to nydus images",
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
		Usage: "Convert an image between OCI and nydus format and push the result",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "source image reference (e.g. registry/repo:tag) or local directory path; can be repeated to stack multiple sources (lower to upper) into one nydus image with a single merged bootstrap",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "target image reference to push",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the nydus binary",
				Value: "nydus",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "scratch directory for conversion (defaults to a temp dir)",
			},
			&cli.UintFlag{
				Name:  "chunk-size",
				Usage: "nydus file chunk size in bytes",
				Value: 1 << 20,
			},
			&cli.UintFlag{
				Name:  "block-group-size",
				Usage: "nydus block group uncompressed size in bytes (must be a multiple of 1MiB)",
				Value: 4 << 20,
			},
			&cli.StringFlag{
				Name:  "compressor",
				Usage: "OCI to nydus: chunk data compressor, none or zstd. nydus to OCI: oci-gzip, oci-zstd or oci-tar, selecting the layer compression of the rebuilt OCI image",
				Value: "zstd",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "convert only the given platform (e.g. linux/amd64); defaults to all",
			},
			&cli.BoolFlag{
				Name:  "source-insecure",
				Usage: "skip TLS certificate verification for the source registry",
			},
			&cli.BoolFlag{
				Name:  "source-plain-http",
				Usage: "use plain HTTP to talk to the source registry",
			},
			&cli.BoolFlag{
				Name:  "target-insecure",
				Usage: "skip TLS certificate verification for the target registry",
			},
			&cli.BoolFlag{
				Name:  "target-plain-http",
				Usage: "use plain HTTP to talk to the target registry",
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

// setupCommand applies the --log-level flag and returns the logger-carrying
// base context shared by every subcommand. The context is canceled on
// SIGINT/SIGTERM so `nydus` subprocesses are terminated and deferred cleanups
// (e.g. work dir removal) still run; the returned stop function releases the
// signal registration and must be deferred by the caller.
func setupCommand(c *cli.Context) (context.Context, context.CancelFunc) {
	if level, err := logrus.ParseLevel(c.String("log-level")); err == nil {
		logrus.SetLevel(level)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, unix.SIGTERM)
	return log.WithLogger(ctx, log.L), stop
}

// scratchWorkDir resolves --work-dir: an explicit directory is created and
// kept; otherwise a temp dir with the given prefix is created and the
// returned cleanup removes it.
func scratchWorkDir(c *cli.Context, prefix string) (string, func(), error) {
	workDir := c.String("work-dir")
	if workDir == "" {
		tmp, err := os.MkdirTemp("", prefix)
		if err != nil {
			return "", nil, errors.Wrap(err, "create work dir")
		}
		return tmp, func() { _ = os.RemoveAll(tmp) }, nil
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", nil, errors.Wrapf(err, "create work dir %q", workDir)
	}
	return workDir, func() {}, nil
}

func runConvert(c *cli.Context) error {
	ctx, stop := setupCommand(c)
	defer stop()

	sources := c.StringSlice("source")
	source := sources[0]
	target := c.String("target")
	appendFiles := c.StringSlice("append-in-bootstrap")
	multiSource := len(sources) > 1

	// The compressor picks the conversion direction, so reject unknown values
	// instead of silently running the wrong one.
	compressor := c.String("compressor")
	toOCI := pipeline.IsOCICompressor(compressor)
	if !toOCI && compressor != "none" && compressor != "zstd" {
		return errors.Errorf("unsupported --compressor %q, expected none, zstd, oci-gzip, oci-zstd or oci-tar", compressor)
	}

	// Detect whether --source is a local directory (instead of an OCI image
	// reference). When the source is a directory, we use ConvertLocalDir
	// which builds a single-layer nydus image directly from the directory
	// tree, excluding any --append-in-bootstrap files that reside inside it.
	isLocalDir := isDir(source)

	platform := platforms.DefaultSpec()
	platformMC := platforms.All
	if p := c.String("platform"); p != "" {
		parsed, err := platforms.Parse(p)
		if err != nil {
			return errors.Wrapf(err, "invalid platform %q", p)
		}
		platform = parsed
		platformMC = platforms.Only(parsed)
	} else if multiSource {
		// Multiple sources are merged into one single-platform manifest, so
		// image sources must be resolved to exactly one platform. Default to
		// the host platform when --platform is not given.
		logrus.Infof("multiple sources: defaulting to platform %s", platforms.Format(platform))
		platformMC = platforms.Only(platform)
	}

	workDir, cleanupWorkDir, err := scratchWorkDir(c, "nydusify-")
	if err != nil {
		return err
	}
	defer cleanupWorkDir()

	contentDir := joinWork(workDir, "content")
	scratchDir := joinWork(workDir, "scratch")
	for _, d := range []string{contentDir, scratchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	provider, err := remote.NewProvider(remote.Option{
		WorkDir:         contentDir,
		SourceInsecure:  c.Bool("source-insecure"),
		SourcePlainHTTP: c.Bool("source-plain-http"),
		TargetInsecure:  c.Bool("target-insecure"),
		TargetPlainHTTP: c.Bool("target-plain-http"),
		PlatformMC:      platformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}

	var newDesc *ocispec.Descriptor

	if toOCI {
		if multiSource || isLocalDir {
			return errors.New("converting back to OCI expects exactly one nydus image as --source")
		}

		logrus.Infof("pulling nydus image %s", source)
		srcDesc, err := provider.Pull(ctx, source, remote.PullAll, remote.Source)
		if err != nil {
			return errors.Wrapf(err, "pull %q", source)
		}

		logrus.Infof("converting image back to OCI format")
		newDesc, err = pipeline.ConvertToOCI(ctx, provider.ContentStore(), srcDesc, pipeline.ToOCIOption{
			BuilderPath: c.String("builder"),
			WorkDir:     scratchDir,
			Compressor:  compressor,
			LogLevel:    c.String("log-level"),
		})
		if err != nil {
			return errors.Wrap(err, "convert to oci")
		}

		logrus.Infof("pushing oci image %s", target)
		if err := provider.Push(ctx, *newDesc, target); err != nil {
			return errors.Wrapf(err, "push %q", target)
		}
		logrus.Infof("done: %s -> %s (%s)", source, target, newDesc.Digest)
		return nil
	}

	if multiSource {
		srcs := make([]pipeline.Source, 0, len(sources))
		for _, s := range sources {
			if isDir(s) {
				srcs = append(srcs, pipeline.Source{Dir: s})
				continue
			}
			logrus.Infof("pulling source image %s", s)
			desc, err := provider.Pull(ctx, s, remote.PullAll, remote.Source)
			if err != nil {
				return errors.Wrapf(err, "pull %q", s)
			}
			srcs = append(srcs, pipeline.Source{Image: &desc})
		}

		logrus.Infof("converting %d sources to nydus format", len(srcs))
		newDesc, err = pipeline.ConvertMultiSource(ctx, provider.ContentStore(), pipeline.MultiSourceOption{
			BuilderPath:       c.String("builder"),
			WorkDir:           scratchDir,
			ChunkSize:         uint32(c.Uint("chunk-size")),
			BlockGroupSize:    uint32(c.Uint("block-group-size")),
			Compressor:        compressor,
			LogLevel:          c.String("log-level"),
			Platform:          platform,
			Sources:           srcs,
			AppendInBootstrap: appendFiles,
		})
		if err != nil {
			return errors.Wrap(err, "convert multiple sources")
		}
	} else if isLocalDir {
		logrus.Infof("converting local directory %s to nydus format", source)
		newDesc, err = pipeline.ConvertLocalDir(ctx, provider.ContentStore(), pipeline.LocalDirOption{
			BuilderPath:       c.String("builder"),
			WorkDir:           scratchDir,
			ChunkSize:         uint32(c.Uint("chunk-size")),
			BlockGroupSize:    uint32(c.Uint("block-group-size")),
			Compressor:        compressor,
			LogLevel:          c.String("log-level"),
			SourceDir:         source,
			AppendInBootstrap: appendFiles,
		})
		if err != nil {
			return errors.Wrap(err, "convert local directory")
		}
	} else {
		logrus.Infof("pulling source image %s", source)
		srcDesc, err := provider.Pull(ctx, source, remote.PullAll, remote.Source)
		if err != nil {
			return errors.Wrapf(err, "pull %q", source)
		}

		logrus.Infof("converting image to nydus format")
		newDesc, err = pipeline.Convert(ctx, provider.ContentStore(), srcDesc, pipeline.Option{
			BuilderPath:    c.String("builder"),
			WorkDir:        scratchDir,
			ChunkSize:      uint32(c.Uint("chunk-size")),
			BlockGroupSize: uint32(c.Uint("block-group-size")),
			Compressor:     c.String("compressor"),
			LogLevel:       c.String("log-level"),
			PlatformMC:     platformMC,
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
			logrus.Infof("image size: oci %s -> nydus %s",
				humanize.IBytes(srcSize), humanize.IBytes(dstSize))
		}
	}

	logrus.Infof("pushing nydus image %s", target)
	if err := provider.Push(ctx, *newDesc, target); err != nil {
		return errors.Wrapf(err, "push %q", target)
	}

	logrus.Infof("done: %s -> %s (%s)", strings.Join(sources, ", "), target, newDesc.Digest)
	return nil
}

// isDir reports whether path exists and is a local directory (as opposed to
// an OCI image reference).
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// totalLayerSize resolves rootDesc (a manifest or a multi-platform index) for
// the requested platform and returns the sum of its layer descriptor sizes.
func totalLayerSize(ctx context.Context, cs content.Store, rootDesc ocispec.Descriptor, platformMC platforms.MatchComparer) (uint64, error) {
	manifestDesc, err := oci.ResolveManifest(ctx, cs, rootDesc, platformMC)
	if err != nil {
		return 0, err
	}

	var manifest ocispec.Manifest
	if err := oci.ReadJSON(ctx, cs, manifestDesc, &manifest); err != nil {
		return 0, errors.Wrap(err, "read manifest")
	}

	var total uint64
	for _, layer := range manifest.Layers {
		if layer.Size > 0 {
			total += uint64(layer.Size)
		}
	}
	return total, nil
}

func checkCommand() *cli.Command {
	return &cli.Command{
		Name:  "check",
		Usage: "Validate the consistency of an OCI and/or nydus image",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "source",
				Aliases: []string{"s"},
				Usage:   "source image reference (OCI or nydus); may be empty",
			},
			&cli.StringFlag{
				Name:    "target",
				Aliases: []string{"t"},
				Usage:   "target image reference (OCI or nydus); may be empty",
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the nydus binary",
				Value: "nydus",
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "directory for checking artifacts and single-image exports",
				Value: "./output",
			},
			&cli.StringFlag{
				Name:  "platform",
				Usage: "check only the given platform (e.g. linux/amd64); defaults to the host platform",
			},
			&cli.BoolFlag{
				Name:  "source-insecure",
				Usage: "skip TLS certificate verification for the source registry",
			},
			&cli.BoolFlag{
				Name:  "source-plain-http",
				Usage: "use plain HTTP to talk to the source registry",
			},
			&cli.BoolFlag{
				Name:  "target-insecure",
				Usage: "skip TLS certificate verification for the target registry",
			},
			&cli.BoolFlag{
				Name:  "target-plain-http",
				Usage: "use plain HTTP to talk to the target registry",
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
	ctx, stop := setupCommand(c)
	defer stop()

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

	// Prepare the work directory. It holds checking scratch state and, for
	// single-image checks, the exported metadata; it is never auto-removed.
	workDir := c.String("work-dir")
	if workDir == "" {
		workDir = "./output"
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return errors.Wrapf(err, "create work dir %q", workDir)
	}

	chk, err := checker.New(checker.Option{
		Source:          source,
		Target:          target,
		BuilderPath:     c.String("builder"),
		WorkDir:         workDir,
		SourceInsecure:  c.Bool("source-insecure"),
		SourcePlainHTTP: c.Bool("source-plain-http"),
		TargetInsecure:  c.Bool("target-insecure"),
		TargetPlainHTTP: c.Bool("target-plain-http"),
		LogLevel:        c.String("log-level"),
		PlatformMC:      platformMC,
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
		Usage: "Mount an OCI or nydus image at a local mountpoint",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "target image reference (OCI or nydus)",
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
				Usage: "path to the nydus binary",
				Value: "nydus",
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
				Name:  "target-insecure",
				Usage: "skip TLS certificate verification for the target registry",
			},
			&cli.BoolFlag{
				Name:  "target-plain-http",
				Usage: "use plain HTTP to talk to the target registry",
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
	ctx, stop := setupCommand(c)
	defer stop()

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

	workDir, cleanupWorkDir, err := scratchWorkDir(c, "nydusify-mount-")
	if err != nil {
		return err
	}
	defer cleanupWorkDir()

	mnt, err := mounter.NewMounter(mounter.MountOption{
		Target:          target,
		Mountpoint:      mountpoint,
		BuilderPath:     c.String("builder"),
		WorkDir:         workDir,
		TargetInsecure:  c.Bool("target-insecure"),
		TargetPlainHTTP: c.Bool("target-plain-http"),
		Prefetch:        c.Bool("prefetch"),
		LogLevel:        c.String("log-level"),
		PlatformMC:      platformMC,
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
		Usage: "Build an ondemand blob from a /trace access pattern and push an optimized nydus image",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "pattern",
				Usage:    "path to a JSON access-pattern file (same format as the /trace endpoint)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "source",
				Aliases:  []string{"s"},
				Usage:    "source nydus image reference",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "optimized nydus image reference to push",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "builder",
				Usage: "path to the nydus binary",
				Value: "nydus",
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
				Name:  "source-insecure",
				Usage: "skip TLS certificate verification for the source registry",
			},
			&cli.BoolFlag{
				Name:  "source-plain-http",
				Usage: "use plain HTTP to talk to the source registry",
			},
			&cli.BoolFlag{
				Name:  "target-insecure",
				Usage: "skip TLS certificate verification for the target registry",
			},
			&cli.BoolFlag{
				Name:  "target-plain-http",
				Usage: "use plain HTTP to talk to the target registry",
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
	ctx, stop := setupCommand(c)
	defer stop()

	platformMC := platforms.Default()
	if p := c.String("platform"); p != "" {
		parsed, err := platforms.Parse(p)
		if err != nil {
			return errors.Wrapf(err, "invalid platform %q", p)
		}
		platformMC = platforms.Only(parsed)
	}

	workDir, cleanupWorkDir, err := scratchWorkDir(c, "nydusify-optimize-")
	if err != nil {
		return err
	}
	defer cleanupWorkDir()

	opt, err := optimizer.NewOptimizer(optimizer.OptimizeOption{
		Source:          c.String("source"),
		Target:          c.String("target"),
		Pattern:         c.String("pattern"),
		BuilderPath:     c.String("builder"),
		WorkDir:         workDir,
		SourceInsecure:  c.Bool("source-insecure"),
		SourcePlainHTTP: c.Bool("source-plain-http"),
		TargetInsecure:  c.Bool("target-insecure"),
		TargetPlainHTTP: c.Bool("target-plain-http"),
		LogLevel:        c.String("log-level"),
		PlatformMC:      platformMC,
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
