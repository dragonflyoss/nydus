// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"text/template"
	"time"

	"github.com/pkg/errors"
)

type NydusdConfig struct {
	EnablePrefetch bool
	NydusdPath     string
	BootstrapPath  string
	ConfigPath     string
	BackendType    string
	BackendConfig  string
	BlobCacheDir   string
	APISockPath    string
	MountPath      string
}

// Nydusd runs nydusd binary.
type Nydusd struct {
	NydusdConfig
}

type daemonInfo struct {
	State string `json:"state"`
}

var configTpl = `
{
	"device": {
		"backend": {
			"type": "{{.BackendType}}",
			"config": {{.BackendConfig}}
		},
		"cache": {
			"type": "blobcache",
			"config": {
				"work_dir": "{{.BlobCacheDir}}"
			}
		}
	},
	"mode": "cached",
	"iostats_files": false,
	"fs_prefetch": {
		"enable": {{.EnablePrefetch}},
		"threads_count": 10,
		"merging_size": 131072
	},
	"digest_validate": true,
	"enable_xattr": true
}
`

func makeConfig(conf NydusdConfig) error {
	tpl := template.Must(template.New("").Parse(configTpl))

	var ret bytes.Buffer
	if conf.BackendType == "" {
		conf.BackendType = "localfs"
		conf.BackendConfig = `{"dir": "/fake"}`
		conf.EnablePrefetch = false
	} else {
		conf.EnablePrefetch = true
	}
	if err := tpl.Execute(&ret, conf); err != nil {
		return errors.New("prepare config template for Nydusd")
	}

	if err := ioutil.WriteFile(conf.ConfigPath, ret.Bytes(), 0644); err != nil {
		return errors.New("write config file for Nydusd")
	}

	return nil
}

// Wait until Nydusd ready by checking daemon state RUNNING
func checkReady(ctx context.Context, sock string) (<-chan bool, error) {
	ready := make(chan bool)

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", sock)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, err := client.Get(fmt.Sprintf("http://unix%s", "/api/v1/daemon"))
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			var info daemonInfo
			if err = json.Unmarshal(body, &info); err != nil {
				continue
			}

			if info.State == "RUNNING" {
				ready <- true
				break
			}
		}
	}()

	return ready, nil
}

func NewNydusd(conf NydusdConfig) (*Nydusd, error) {
	if err := makeConfig(conf); err != nil {
		return nil, errors.New("create config file for Nydusd")
	}
	return &Nydusd{
		NydusdConfig: conf,
	}, nil
}

func (nydusd *Nydusd) Mount() error {
	nydusd.Umount()

	var args []string
	args = []string{
		"--config",
		nydusd.ConfigPath,
		"--mountpoint",
		nydusd.MountPath,
		"--bootstrap",
		nydusd.BootstrapPath,
		"--apisock",
		nydusd.APISockPath,
		"--log-level",
		"error",
	}

	cmd := exec.Command(nydusd.NydusdPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := make(chan error)
	go func() {
		runErr <- cmd.Run()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready, err := checkReady(ctx, nydusd.APISockPath)
	if err != nil {
		return errors.New("check Nydusd state")
	}

	select {
	case err := <-runErr:
		if err != nil {
			return errors.Wrap(err, "run Nydusd binary")
		}
	case <-ready:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("timeout to wait Nydusd ready")
	}

	return nil
}

func (nydusd *Nydusd) Umount() error {
	if _, err := os.Stat(nydusd.MountPath); err == nil {
		cmd := exec.Command("umount", nydusd.MountPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
