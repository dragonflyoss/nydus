package optimizer

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("module", "optimizer")

func isSignalKilled(err error) bool {
	return strings.Contains(err.Error(), "signal: killed")
}

type BuildOption struct {
	BuilderPath       string
	PrefetchFilesPath string
	BootstrapPath     string
	BackendType       string
	BackendConfig     string
	// `BlobDir` is used to store optimized blob,
	// Beside, `BlobDir` is also used to store the original blobs when backend is localfs
	BlobDir             string
	OutputBootstrapPath string
	OutputJSONPath      string
	Timeout             *time.Duration
}

type outputJSON struct {
	Blobs []string `json:"blobs"`
}

func Build(option BuildOption) (string, error) {
	outputJSONPath := option.OutputJSONPath
	args := []string{
		"optimize",
		"--log-level",
		"warn",
		"--prefetch-files",
		option.PrefetchFilesPath,
		"--bootstrap",
		option.BootstrapPath,
		"--output-blob-dir",
		option.BlobDir,
		"--output-bootstrap",
		option.OutputBootstrapPath,
		"--output-json",
		outputJSONPath,
	}

	if option.BackendType == "localfs" {
		args = append(args, "--blob-dir", option.BlobDir)
	} else {
		args = append(args, "--backend-type", option.BackendType)
		args = append(args, "--backend-config", option.BackendConfig)
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if option.Timeout != nil {
		ctx, cancel = context.WithTimeout(ctx, *option.Timeout)
		defer cancel()
	}
	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Run(); err != nil {
		if isSignalKilled(err) && option.Timeout != nil {
			logrus.WithError(err).Errorf("fail to run %v %+v, possibly due to timeout %v", option.BuilderPath, args, *option.Timeout)
		} else {
			logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		}
		return "", errors.Wrap(err, "run merge command")
	}

	outputBytes, err := os.ReadFile(outputJSONPath)
	if err != nil {
		return "", errors.Wrapf(err, "read file %s", outputJSONPath)
	}
	var output outputJSON
	err = json.Unmarshal(outputBytes, &output)
	if err != nil {
		return "", errors.Wrapf(err, "unmarshal output json file %s", outputJSONPath)
	}
	blobID := output.Blobs[len(output.Blobs)-1]

	logrus.Infof("build success for prefetch blob : %s", blobID)
	return blobID, nil
}
