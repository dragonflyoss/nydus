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
	"testing"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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

type MountInfo struct {
	MountPoint string `json:"mountpoint"`
}

type DaemonInfo struct {
	BackendCollection map[string]MountInfo `json:"backend_collection"`
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
	// Overlay config.
	OvlUpperDir string
	OvlWorkDir  string
	Writable    bool
}

type Nydusd struct {
	NydusdConfig
	Pid    int
	client *http.Client
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

var configOvlTpl = `
 {
	"version": 2,
	"backend": {
		"type": "localfs",
		"localfs": {{.BackendConfig}}
	},
	"cache": {
		"type": "blobcache",
		"filecache": {
			"work_dir": "{{.BlobCacheDir}}"
		}
	},
	"rafs": {
		"mode": "{{.RafsMode}}",
		"enable_xattr": true
	},
	"overlay": {
		"upper_dir": "{{.OvlUpperDir}}",
		"work_dir": "{{.OvlWorkDir}}"
	}
}
 `

type TemplateType int

const (
	NydusdConfigTpl TemplateType = iota
	NydusdOvlConfigTpl
)

func makeConfig(tplType TemplateType, conf NydusdConfig) error {
	var tpl *template.Template

	switch tplType {
	case NydusdConfigTpl:
		tpl = template.Must(template.New("").Parse(configTpl))
	case NydusdOvlConfigTpl:
		tpl = template.Must(template.New("").Parse(configOvlTpl))
	default:
		return errors.New("unknown template type")
	}

	var ret bytes.Buffer
	if err := tpl.Execute(&ret, conf); err != nil {
		return errors.New("prepare config template for Nydusd")
	}

	if err := os.WriteFile(conf.ConfigPath, ret.Bytes(), 0600); err != nil {
		return errors.Wrapf(err, "write config file for Nydusd")
	}

	return nil
}

func (nydusd *Nydusd) CheckReady(ctx context.Context) <-chan bool {
	ready := make(chan bool)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, err := nydusd.client.Get(fmt.Sprintf("http://unix%s", "/api/v1/daemon"))
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
	if err := makeConfig(NydusdConfigTpl, conf); err != nil {
		return nil, errors.Wrap(err, "create config file for Nydusd")
	}

	transport := &http.Transport{
		MaxIdleConns:        3,
		MaxIdleConnsPerHost: 3,
		MaxConnsPerHost:     10,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", conf.APISockPath)
		},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	return &Nydusd{
		NydusdConfig: conf,
		client:       client,
	}, nil
}

func NewNydusdWithOverlay(conf NydusdConfig) (*Nydusd, error) {
	if err := makeConfig(NydusdOvlConfigTpl, conf); err != nil {
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
		"warn",
	}
	if len(nydusd.ConfigPath) > 0 {
		args = append(args, "--config", nydusd.ConfigPath)
	}
	if len(nydusd.BootstrapPath) > 0 {
		args = append(args, "--bootstrap", nydusd.BootstrapPath)
	}
	if nydusd.Writable {
		args = append(args, "--writable")
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

	ready := nydusd.CheckReady(ctx)

	select {
	case err := <-runErr:
		if err != nil {
			return errors.Wrap(err, "run Nydusd binary")
		}
	case <-ready:
		nydusd.Pid = cmd.Process.Pid
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("timeout to wait Nydusd ready")
	}

	return nil
}

func (nydusd *Nydusd) GetDaemonInfoByAPI(t *testing.T) *DaemonInfo {
	resp, err := nydusd.client.Get("http://unix/api/v1/daemon")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	daemonInfo := DaemonInfo{}
	err = json.Unmarshal(body, &daemonInfo)
	require.NoError(t, err)

	return &daemonInfo
}

func (nydusd *Nydusd) MountByAPI(t *testing.T, config NydusdConfig) {
	err := makeConfig(NydusdConfigTpl, config)
	require.NoError(t, err)

	f, err := os.Open(config.ConfigPath)
	require.NoError(t, err)
	defer f.Close()

	rafsConfig, err := io.ReadAll(f)
	require.NoError(t, err)

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

	body, err := json.Marshal(nydusdConfig)
	require.NoError(t, err)

	resp, err := nydusd.client.Post(
		fmt.Sprintf("http://unix/api/v1/mount?mountpoint=%s", config.MountPath),
		"application/json",
		bytes.NewBuffer(body),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func (nydusd *Nydusd) UmountByAPI(t *testing.T, mountPath string) {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://unix/api/v1/mount?mountpoint=%s", mountPath), nil)
	require.NoError(t, err)

	resp, err := nydusd.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func (nydusd *Nydusd) Umount() error {
	if _, err := os.Stat(nydusd.MountPath); err == nil {
		cmd := exec.Command("umount", nydusd.MountPath)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func (nydusd *Nydusd) GetGlobalMetrics() (*GlobalMetrics, error) {
	resp, err := nydusd.client.Get(fmt.Sprintf("http://unix%s", "/api/v1/metrics"))
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
	resp, err := nydusd.client.Get(fmt.Sprintf("http://unix/api/v1/metrics/files?id=%s", id))
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
	resp, err := nydusd.client.Get(fmt.Sprintf("http://unix/api/v1/metrics/backend?id=%s", id))
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
	resp, err := nydusd.client.Get("http://unix/api/v1/metrics/files?latest=true")
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
	args := ""
	if len(id) > 0 {
		args += "?id=" + id
	}

	resp, err := nydusd.client.Get(fmt.Sprintf("http://unix/api/v1/metrics/pattern%s", args))
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
	args := ""
	if len(id) > 0 {
		args += "?id=" + id
	}

	resp, err := nydusd.client.Get(fmt.Sprintf("http://unix/api/v1/metrics/blobcache%s", args))
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
	resp, err := nydusd.client.Get("http://unix/api/v1/metrics/inflight")
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
