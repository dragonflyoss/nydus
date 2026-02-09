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
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
	ReadCount       uint64 `json:"read_count"`
	ReadAmountTotal uint64 `json:"read_amount_total"`
	ReadErrors      uint64 `json:"read_errors"`
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
	EnablePrefetch               bool
	NydusdPath                   string
	BootstrapPath                string
	ConfigPath                   string
	BackendType                  string
	BackendConfig                string
	ExternalBackendConfigPath    string
	ExternalBackendProxyCacheDir string
	BlobCacheDir                 string
	APISockPath                  string
	MountPath                    string
	RafsMode                     string
	DigestValidate               bool
	CacheType                    string
	CacheCompressed              bool
	IOStatsFiles                 bool
	LatestReadFiles              bool
	AccessPattern                bool
	PrefetchFiles                []string
	AmplifyIO                    uint64
	ChunkDedupDb                 string
	// Hot Upgrade config.
	Upgrade            bool
	SupervisorSockPath string
	// Overlay config.
	OvlUpperDir string
	OvlWorkDir  string
	Writable    bool
}

type Nydusd struct {
	client *http.Client
	cmd    *exec.Cmd
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
		 "external_backend": {
		 	 "config_path": "{{.ExternalBackendConfigPath}}"
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

func newNydusd(conf NydusdConfig) (*Nydusd, error) {
	args := []string{
		"--mountpoint",
		conf.MountPath,
		"--apisock",
		conf.APISockPath,
		"--log-level",
		"info",
		"--thread-num",
		"10",
	}
	if len(conf.ConfigPath) > 0 {
		args = append(args, "--config", conf.ConfigPath)
	}
	if len(conf.BootstrapPath) > 0 {
		args = append(args, "--bootstrap", conf.BootstrapPath)
	}
	if len(conf.ChunkDedupDb) > 0 {
		args = append(args, "--dedup-db", conf.ChunkDedupDb)
	}
	if conf.Upgrade {
		args = append(args, "--upgrade")
	}
	if len(conf.SupervisorSockPath) > 0 {
		args = append(args, "--supervisor", conf.SupervisorSockPath, "--id", uuid.NewString())
	}
	if conf.Writable {
		args = append(args, "--writable")
	}

	logrus.Infof("commad:%s %s", conf.NydusdPath, strings.Join(args, " "))
	cmd := exec.Command(conf.NydusdPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", conf.APISockPath)
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	nydusd := &Nydusd{
		client:       client,
		cmd:          cmd,
		NydusdConfig: conf,
	}

	return nydusd, nil
}

func NewNydusd(conf NydusdConfig) (*Nydusd, error) {
	if err := makeConfig(NydusdConfigTpl, conf); err != nil {
		return nil, errors.Wrap(err, "create config file for Nydusd")
	}

	nydusd, err := newNydusd(conf)
	if err != nil {
		return nil, err
	}

	return nydusd, nil
}

func NewNydusdWithOverlay(conf NydusdConfig) (*Nydusd, error) {
	if err := makeConfig(NydusdOvlConfigTpl, conf); err != nil {
		return nil, errors.Wrap(err, "create config file for Nydusd")
	}

	nydusd, err := newNydusd(conf)
	if err != nil {
		return nil, err
	}

	return nydusd, nil
}

func NewNydusdWithContext(ctx Context) (*Nydusd, error) {
	conf := NydusdConfig{
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   ctx.Env.BootstrapPath,
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		BlobCacheDir:    ctx.Env.CacheDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		MountPath:       filepath.Join(ctx.Env.WorkDir, "mnt"),
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
		AmplifyIO:       ctx.Runtime.AmplifyIO,
		ChunkDedupDb:    ctx.Runtime.ChunkDedupDb,
	}

	if err := makeConfig(NydusdConfigTpl, conf); err != nil {
		return nil, errors.Wrap(err, "create config file for Nydusd")
	}

	nydusd, err := newNydusd(conf)
	if err != nil {
		return nil, err
	}

	return nydusd, nil
}

func (nydusd *Nydusd) Run() (chan error, error) {
	errChan := make(chan error)
	if err := nydusd.cmd.Start(); err != nil {
		return errChan, err
	}

	go func() {
		errChan <- nydusd.cmd.Wait()
	}()

	time.Sleep(2 * time.Second)

	return errChan, nil
}

func (nydusd *Nydusd) Mount() error {
	_, err := nydusd.Run()
	if err != nil {
		return err
	}

	err = nydusd.WaitStatus("RUNNING")
	if err != nil {
		return err
	}

	if nydusd.EnablePrefetch {
		nydusd.waitPrefetch()
	}

	return nil
}

func (nydusd *Nydusd) MountByAPI(config NydusdConfig) error {
	tpl := template.Must(template.New("").Parse(configTpl))

	var ret bytes.Buffer
	if err := tpl.Execute(&ret, config); err != nil {
		return errors.New("prepare config template for Nydusd")
	}
	rafsConfig := ret.String()

	nydusdConfig := struct {
		Bootstrap     string   `json:"source"`
		RafsConfig    string   `json:"config"`
		FsType        string   `json:"fs_type"`
		PrefetchFiles []string `json:"prefetch_files"`
	}{
		Bootstrap:     config.BootstrapPath,
		RafsConfig:    rafsConfig,
		FsType:        "rafs",
		PrefetchFiles: config.PrefetchFiles,
	}

	body, err := json.Marshal(nydusdConfig)
	if err != nil {
		return err
	}
	_, err = nydusd.client.Post(
		fmt.Sprintf("http://unix/api/v1/mount?mountpoint=%s", config.MountPath),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}

	if config.EnablePrefetch {
		nydusd.waitPrefetch()
	}

	return nil
}

func (nydusd *Nydusd) Umount() error {
	if _, err := os.Stat(nydusd.MountPath); err == nil {
		cmd := exec.Command("umount", "-l", nydusd.MountPath)
		cmd.Stdout = os.Stdout
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func (nydusd *Nydusd) UmountByAPI(subPath string) error {
	url := fmt.Sprintf("http://unix/api/v1/mount?mountpoint=%s", subPath)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	resp, err := nydusd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (nydusd *Nydusd) WaitStatus(states ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	var currentState string

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout to wait nydusd state, expected: %s, current: %s", states, currentState)
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
		currentState = info.State

		for _, state := range states {
			if currentState == state {
				return nil
			}
		}
	}
}

func (nydusd *Nydusd) StartByAPI() error {
	req, err := http.NewRequest("PUT", "http://unix/api/v1/daemon/start", nil)
	if err != nil {
		return err
	}

	resp, err := nydusd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (nydusd *Nydusd) SendFd() error {
	req, err := http.NewRequest("PUT", "http://unix/api/v1/daemon/fuse/sendfd", nil)
	if err != nil {
		return err
	}

	resp, err := nydusd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (nydusd *Nydusd) Takeover() error {
	req, err := http.NewRequest("PUT", "http://unix/api/v1/daemon/fuse/takeover", nil)
	if err != nil {
		return err
	}

	resp, err := nydusd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (nydusd *Nydusd) Exit() error {
	req, err := http.NewRequest("PUT", "http://unix/api/v1/daemon/exit", nil)
	if err != nil {
		return err
	}

	resp, err := nydusd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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

func (nydusd *Nydusd) GetBackendMetrics(id ...string) (*BackendMetrics, error) {
	requestURL := "http://unix/api/v1/metrics/backend"
	if len(id) == 1 {
		requestURL = fmt.Sprintf("http://unix/api/v1/metrics/backend?id=%s", id[0])
	} else if len(id) > 1 {
		return nil, errors.Errorf("Multiple id are not allowed")
	}
	resp, err := nydusd.client.Get(requestURL)
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

func (nydusd *Nydusd) Verify(t *testing.T, expectedFileTree map[string]*File) {
	nydusd.VerifyByPath(t, expectedFileTree, "")
}

func (nydusd *Nydusd) VerifyByPath(t *testing.T, expectedFileTree map[string]*File, subPath string) {
	actualFiles := map[string]*File{}
	mountPath := filepath.Join(nydusd.MountPath, subPath)
	err := filepath.WalkDir(mountPath, func(path string, _ fs.DirEntry, err error) error {
		require.Nil(t, err)
		targetPath, err := filepath.Rel(mountPath, path)
		require.NoError(t, err)
		if targetPath == "." || targetPath == ".." {
			return nil
		}
		file := NewFile(t, path, targetPath)
		actualFiles[targetPath] = file
		if expectedFileTree[targetPath] != nil {
			expectedFileTree[targetPath].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in OCI layer", targetPath)
		}

		return nil
	})
	require.NoError(t, err)

	for targetPath, file := range expectedFileTree {
		if actualFiles[targetPath] != nil {
			actualFiles[targetPath].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in nydus layer: %s %s", targetPath, nydusd.MountPath, nydusd.BootstrapPath)
		}
	}
}

func Verify(t *testing.T, ctx Context, expectedFileTree map[string]*File) {
	nydusd, err := NewNydusdWithContext(ctx)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)
	defer nydusd.Umount()
	nydusd.Verify(t, expectedFileTree)
}

func (nydusd *Nydusd) waitPrefetch() {
	// Wait for prefetch to start and stabilize
	deadline := time.Now().Add(10 * time.Second)
	var lastReadCount uint64
	stableCount := 0

	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		metrics, err := nydusd.GetBackendMetrics()
		if err != nil {
			continue
		}

		if metrics.ReadCount == 0 {
			continue
		}

		// Check if read count is stable (prefetch completed)
		if metrics.ReadCount == lastReadCount {
			stableCount++
			if stableCount >= 3 {
				return
			}
		} else {
			stableCount = 0
			lastReadCount = metrics.ReadCount
		}
	}
}
