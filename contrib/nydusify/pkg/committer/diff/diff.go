// Ported from buildkit project, copyright The buildkit Authors.
// https://github.com/moby/buildkit

package diff

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/moby/buildkit/util/overlay"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/committer/diff/archive"
)

func overlaySupportIndex() bool {
	if _, err := os.Stat("/sys/module/overlay/parameters/index"); err == nil {
		return true
	}
	return false
}

// Ported from github.com/moby/buildkit/util/overlay/overlay_linux.go
// Modified overlayfs temp mount handle.
//
// WriteUpperdir writes a layer tar archive into the specified writer, based on
// the diff information stored in the upperdir.
func writeUpperdir(ctx context.Context, appendMount func(path string), withPaths []string, withoutPaths []string, w io.Writer, upperdir string, lower []mount.Mount) error {
	emptyLower, err := os.MkdirTemp("", "buildkit") // empty directory used for the lower of diff view
	if err != nil {
		return errors.Wrapf(err, "failed to create temp dir")
	}
	defer os.Remove(emptyLower)

	options := []string{
		fmt.Sprintf("lowerdir=%s", strings.Join([]string{upperdir, emptyLower}, ":")),
	}
	if overlaySupportIndex() {
		options = append(options, "index=off")
	}
	upperView := []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}

	return mount.WithTempMount(ctx, lower, func(lowerRoot string) error {
		return mount.WithTempMount(ctx, upperView, func(upperViewRoot string) error {
			cw := archive.NewChangeWriter(&cancellableWriter{ctx, w}, upperViewRoot)
			if err := Changes(ctx, appendMount, withPaths, withoutPaths, cw.HandleChange, upperdir, upperViewRoot, lowerRoot); err != nil {
				if err2 := cw.Close(); err2 != nil {
					return errors.Wrapf(err, "failed to record upperdir changes (close error: %v)", err2)
				}
				return errors.Wrapf(err, "failed to record upperdir changes")
			}
			return cw.Close()
		})
	})
}

func Diff(ctx context.Context, appendMount func(path string), withPaths []string, withoutPaths []string, writer io.Writer, lowerDirs, upperDir string) error {
	emptyLower, err := os.MkdirTemp("", "nydus-cli-diff")
	if err != nil {
		return errors.Wrapf(err, "create temp dir")
	}
	defer os.Remove(emptyLower)

	lowerDirs += fmt.Sprintf(":%s", emptyLower)

	options := []string{
		fmt.Sprintf("lowerdir=%s", lowerDirs),
	}
	if overlaySupportIndex() {
		options = append(options, "index=off")
	}
	lower := []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}

	options = []string{
		fmt.Sprintf("lowerdir=%s:%s", upperDir, lowerDirs),
	}
	if overlaySupportIndex() {
		options = append(options, "index=off")
	}
	upper := []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}

	upperDir, err = overlay.GetUpperdir(lower, upper)
	if err != nil {
		return errors.Wrap(err, "get upper dir")
	}

	if err = writeUpperdir(ctx, appendMount, withPaths, withoutPaths, &cancellableWriter{ctx, writer}, upperDir, lower); err != nil {
		return errors.Wrap(err, "write diff")
	}

	return nil
}
