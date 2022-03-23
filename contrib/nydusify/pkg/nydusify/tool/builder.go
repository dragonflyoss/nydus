package tool

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("module", "builder")

type ConvertOption struct {
	BuilderPath string

	BootstrapPath    string
	BlobPath         string
	RafsVersion      string
	SourcePath       string
	ChunkDictPath    string
	PrefetchPatterns string
}

type MergeOption struct {
	BuilderPath string

	SourceBootstrapPaths []string
	TargetBootstrapPath  string
	ChunkDictPath        string
	PrefetchPatterns     string
}

func Convert(option ConvertOption) error {
	args := []string{
		"create",
		"--log-level",
		"warn",
		"--prefetch-policy",
		"fs",
		"--bootstrap",
		option.BootstrapPath,
		"--blob",
		option.BlobPath,
		"--source-type",
		"directory",
		"--whiteout-spec",
		"none",
		"--fs-version",
		option.RafsVersion,
		"--blob-offset",
		// Add blob offset for chunk info with size_of(tar_header) * 2.
		"1024",
	}
	if option.RafsVersion != "" {
		// FIXME: these options should be handled automatically in builder (nydus-image).
		args = append(args, "--disable-check")
	}
	if option.ChunkDictPath != "" {
		args = append(args, "--chunk-dict", fmt.Sprintf("bootstrap=%s", option.ChunkDictPath))
	}
	if option.PrefetchPatterns == "" {
		option.PrefetchPatterns = "/"
	}
	args = append(args, option.SourcePath)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	cmd.Stdin = strings.NewReader(option.PrefetchPatterns)

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}

func Merge(option MergeOption) error {
	args := []string{
		"merge",
		"--prefetch-policy",
		"fs",
		"--bootstrap",
		option.TargetBootstrapPath,
	}
	if option.ChunkDictPath != "" {
		args = append(args, "--chunk-dict", fmt.Sprintf("bootstrap=%s", option.ChunkDictPath))
	}
	if option.PrefetchPatterns == "" {
		option.PrefetchPatterns = "/"
	}
	args = append(args, option.SourceBootstrapPaths...)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	cmd.Stdin = strings.NewReader(option.PrefetchPatterns)

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}
