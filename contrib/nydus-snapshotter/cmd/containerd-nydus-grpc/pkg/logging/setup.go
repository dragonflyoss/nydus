/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package logging

import (
	"context"

	"github.com/containerd/containerd/log"
	"github.com/sirupsen/logrus"
)

func SetUp(logLevel string) error {
	lvl, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: log.RFC3339NanoFixed,
	})
	return nil
}

func WithContext() context.Context {
	return log.WithLogger(context.Background(), log.L)
}
