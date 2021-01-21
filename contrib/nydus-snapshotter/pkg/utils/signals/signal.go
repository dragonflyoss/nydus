/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package signals

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	once            sync.Once
	stop            chan struct{}
	shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
)

func SetupSignalHandler() (stopCh <-chan struct{}) {
	// make sure SetupSignalHandler will not call twice
	once.Do(func() {
		stop = make(chan struct{})
		c := make(chan os.Signal, 2)
		signal.Notify(c, shutdownSignals...)
		go func() {
			<-c
			close(stop)
			<-c
			os.Exit(1)
		}()
	})
	return stop
}
