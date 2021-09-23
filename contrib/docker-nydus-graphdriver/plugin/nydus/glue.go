// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

package nydus

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	NudusdConfigPath = "/nydus/config.json"
	NydusdBin        = "/nydus/nydusd"
	NydusdSocket     = "/nydus/api.sock"
)

type Nydus struct {
	command *exec.Cmd
}

func New() *Nydus {
	return &Nydus{}
}

type DaemonInfo struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type errorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func getDaemonStatus(socket string) error {
	transport := http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", socket)
		},
	}

	client := http.Client{Transport: &transport, Timeout: 30 * time.Second}

	if resp, err := client.Get("http://unix/api/v1/daemon"); err != nil {
		return err
	} else {
		defer resp.Body.Close()
		if b, err := ioutil.ReadAll(resp.Body); err != nil {
			return err
		} else {

			if resp.StatusCode >= 400 {
				var message errorMessage
				json.Unmarshal(b, &message)
				return errors.Errorf("request error, status = %d, message %s", resp.StatusCode, message)
			}

			var info DaemonInfo
			if err = json.Unmarshal(b, &info); err != nil {
				return err
			} else {
				if info.State != "RUNNING" {
					return errors.Errorf("nydus is not ready. current stat %s", info.State)
				}
			}
		}
	}

	return nil
}

func (nydus *Nydus) Mount(bootstrap, mountpoint string) error {
	args := []string{
		"--apisock", NydusdSocket,
		"--log-level", "info",
		"--thread-num", "4",
		"--bootstrap", bootstrap,
		"--config", NudusdConfigPath,
		"--mountpoint", mountpoint,
	}

	cmd := exec.Command(NydusdBin, args...)
	logrus.Infof("Start nydusd. %s", cmd.String())
	// Redirect logs from nydusd daemon to a proper place.
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start nydusd")
	}

	nydus.command = cmd
	ready := false

	// return error if nydusd does not reach normal state after elapse.
	for i := 0; i < 30; i += 1 {
		err := getDaemonStatus(NydusdSocket)
		if err == nil {
			ready = true
			break
		} else {
			logrus.Error(err)
			time.Sleep(100 * time.Millisecond)
		}
	}

	if !ready {
		logrus.Errorf("It take too long until nydusd gets RUNNING")
		cmd.Process.Kill()
		cmd.Wait()
	}

	return nil
}
