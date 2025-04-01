/*
 * Copyright (c) 2025. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tool

import (
	"context"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("module", "builder")

type CheckOption struct {
	BuilderPath string
}

func CheckBootstrap(option CheckOption, bootstrapPath string) error {
	args := []string{
		"check",
		"--bootstrap",
		bootstrapPath,
		"-v",
	}

	logrus.Debugf("\tCommand: %s %s", option.BuilderPath, strings.Join(args, " "))

	cmd := exec.CommandContext(context.Background(), option.BuilderPath, args...)
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()

	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Errorf("fail to run %v %+v", option.BuilderPath, args)
		return err
	}

	return nil
}
