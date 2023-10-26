// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
)

type GlobalMetrics struct {
	FilesAccountEnabled bool     `json:"files_account_enabled"`
	MeasureLatency      bool     `json:"measure_latency"`
	AccessPattern       bool     `json:"access_pattern_enabled"`
	DataRead            uint64   `json:"data_read"`
	FOPS                []uint64 `json:"fop_hits"`
}

type FileMetrics struct {
}

type BackendMetrics struct {
}

type AccessPatternMetrics struct {
	Ino                  uint64 `json:"ino"`
	NRRead               uint64 `json:"nr_read"`
	FirstAccessTimeSecs  uint   `json:"first_access_time_secs"`
	FirstAccessTimeNanos uint64 `json:"first_access_time_nanos"`
}

type BlobCacheMetrics struct {
	PrefetchDataAmount uint64 `json:"prefetch_data_amount"`
}

type InflightMetrics struct {
	Ino uint64 `json:"inode"`
}

type NydusdConfig struct {
	EnablePrefetch  bool
	NydusdPath      string
	BootstrapPath   string
	ConfigPath      string
	BackendType     string
	BackendConfig   string
	BlobCacheDir    string
	APISockPath     string
	MountPath       string
	RafsMode        string
	DigestValidate  bool
	CacheType       string
	CacheCompressed bool
	IOStatsFiles    bool
	LatestReadFiles bool
	AccessPattern   bool
	PrefetchFiles   []string
	AmplifyIO       uint64
}

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
			 "type": "{{.CacheType}}",
			 "config": {
				 "compressed": {{.CacheCompressed}},
				 "work_dir": "{{.BlobCacheDir}}"
			 }
		 }
	 },
	 "mode": "{{.RafsMode}}",
	 "iostats_files": {{.IOStatsFiles}},
	 "fs_prefetch": {
		 "enable": {{.EnablePrefetch}},
		 "threads_count": 10,
		 "merging_size": 131072
	 },
	 "digest_validate": {{.DigestValidate}},
	 "enable_xattr": true,
     "latest_read_files": {{.LatestReadFiles}},
     "access_pattern": {{.AccessPattern}},
     "amplify_io": {{.AmplifyIO}}
 }
 `

func makeConfig(conf NydusdConfig) error {
	tpl := template.Must(template.New("").Parse(configTpl))

	var ret bytes.Buffer
	if err := tpl.Execute(&ret, conf); err != nil {
		return errors.New("prepare config template for Nydusd")
	}

	if err := os.WriteFile(conf.ConfigPath, ret.Bytes(), 0600); err != nil {
		return errors.Wrapf(err, "write config file for Nydusd")
	}

	return nil
}

func CheckReady(ctx context.Context, sock string) <-chan bool {
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

			body, err := io.ReadAll(resp.Body)
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

	return ready
}

func NewNydusd(conf NydusdConfig) (*Nydusd, error) {
	if err := makeConfig(conf); err != nil {
		return nil, errors.Wrap(err, "create config file for Nydusd")
	}
	return &Nydusd{
		NydusdConfig: conf,
	}, nil
}

func (nydusd *Nydusd) Mount() error {
	_ = nydusd.Umount()

	args := []string{
		"--mountpoint",
		nydusd.MountPath,
		"--apisock",
		nydusd.APISockPath,
		"--log-level",
		"error",
	}
	if len(nydusd.ConfigPath) > 0 {
		args = append(args, "--config", nydusd.ConfigPath)
	}
	if len(nydusd.BootstrapPath) > 0 {
		args = append(args, "--bootstrap", nydusd.BootstrapPath)
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

	ready := CheckReady(ctx, nydusd.APISockPath)

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

func (nydusd *Nydusd) MountByAPI(config NydusdConfig) error {

	err := makeConfig(config)
	if err != nil {
		return err
	}
	f, err := os.Open(config.ConfigPath)
	if err != nil {
		return err
	}
	defer f.Close()
	rafsConfig, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	nydusdConfig := struct {
		Bootstrap     string   `json:"source"`
		RafsConfig    string   `json:"config"`
		FsType        string   `json:"fs_type"`
		PrefetchFiles []string `json:"prefetch_files"`
	}{
		Bootstrap:     config.BootstrapPath,
		RafsConfig:    string(rafsConfig),
		FsType:        "rafs",
		PrefetchFiles: config.PrefetchFiles,
	}

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	body, err := json.Marshal(nydusdConfig)
	if err != nil {
		return err
	}
	_, err = client.Post(
		fmt.Sprintf("http://unix/api/v1/mount?mountpoint=%s", config.MountPath),
		"application/json",
		bytes.NewBuffer(body),
	)

	return err
}

func (nydusd *Nydusd) Umount() error {
	if _, err := os.Stat(nydusd.MountPath); err == nil {
		cmd := exec.Command("umount", nydusd.MountPath)
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func (nydusd *Nydusd) GetGlobalMetrics() (*GlobalMetrics, error) {

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(fmt.Sprintf("http://unix%s", "/api/v1/metrics"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info GlobalMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (nydusd *Nydusd) GetFilesMetrics(id string) (map[string]FileMetrics, error) {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(fmt.Sprintf("http://unix/api/v1/metrics/files?id=%s", id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	info := make(map[string]FileMetrics)
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return info, nil
}

func (nydusd *Nydusd) GetBackendMetrics(id string) (*BackendMetrics, error) {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(fmt.Sprintf("http://unix/api/v1/metrics/backend?id=%s", id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info BackendMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (nydusd *Nydusd) GetLatestFileMetrics() ([][]uint64, error) {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get("http://unix/api/v1/metrics/files?latest=true")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info [][]uint64
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return info, nil
}

func (nydusd *Nydusd) GetAccessPatternMetrics(id string) ([]AccessPatternMetrics, error) {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	args := ""
	if len(id) > 0 {
		args += "?id=" + id
	}

	resp, err := client.Get(fmt.Sprintf("http://unix/api/v1/metrics/pattern%s", args))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if strings.Contains(string(body), "Pattern(Metrics(Stats(NoCounter)))") {
		return nil, nil
	}

	var info []AccessPatternMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return info, nil
}

func (nydusd *Nydusd) GetBlobCacheMetrics(id string) (*BlobCacheMetrics, error) {

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	args := ""
	if len(id) > 0 {
		args += "?id=" + id
	}

	resp, err := client.Get(fmt.Sprintf("http://unix/api/v1/metrics/blobcache%s", args))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info BlobCacheMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (nydusd *Nydusd) GetInflightMetrics() (*InflightMetrics, error) {

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", nydusd.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get("http://unix/api/v1/metrics/inflight")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info InflightMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, err
}
