/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package signals

import (
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetupSignalHandler(t *testing.T) {
	signal := SetupSignalHandler()
	var expected int32 = 2
	var actual int32
	var func1 = func(stop <-chan struct{}) {
		<-stop
		atomic.AddInt32(&actual, 1)
	}
	var func2 = func(stop <-chan struct{}) {
		<-stop
		atomic.AddInt32(&actual, 1)
	}
	go func1(signal)
	go func2(signal)
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	time.Sleep(1 * time.Second)
	require.Equal(t, actual, expected)
}
