package tool

import (
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("module", "builder")

type ConvertOption struct {
	BuilderPath string

	BootstrapPath string
	BlobPath      string
	RafsVersion   string
	SourcePath    string
}

type MergeOption struct {
	BuilderPath string

	SourceBootstrapPaths []string
	TargetBootstrapPath  string
}

func Convert(option ConvertOption) error {
	args := []string{
		"create",
		"--log-level",
		"warn",
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
		"1024",
	}
	if option.RafsVersion != "" {
		// FIXME: these options should be handled automatically in builder (nydus-image).
		args = append(args, "--disable-check")
	}
	args = append(args, option.SourcePath)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}

func Merge(option MergeOption) error {
	args := []string{
		"merge",
		"--bootstrap",
		option.TargetBootstrapPath,
	}
	args = append(args, option.SourceBootstrapPaths...)

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args[:], " "))

	cmd := exec.Command(option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}
