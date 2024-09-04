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
	"time"

	"github.com/pkg/errors"
)

// SnapshotterClient communicates with nydus-snapshotter via
// the system controller endpoint unix socket of nydus-snapshotter.
type SnapshotterClient struct {
	client *http.Client
}

type DaemonInfoFromSnapshotter struct {
	ID                    string  `json:"id"`
	Pid                   int     `json:"pid"`
	APISock               string  `json:"api_socket"`
	SupervisorPath        string  `json:"supervisor_path"`
	Reference             int     `json:"reference"`
	HostMountpoint        string  `json:"mountpoint"`
	StartupCPUUtilization float64 `json:"startup_cpu_utilization"`
	MemoryRSS             float64 `json:"memory_rss_kb"`
	ReadData              float32 `json:"read_data_kb"`

	Instances map[string]rafsInstanceInfo `json:"instances"`
}

type rafsInstanceInfo struct {
	SnapshotID  string `json:"snapshot_id"`
	SnapshotDir string `json:"snapshot_dir"`
	Mountpoint  string `json:"mountpoint"`
	ImageID     string `json:"image_id"`
}

type UpgradeRequest struct {
	NydusdPath string `json:"nydusd_path"`
	Version    string `json:"version"`
	Policy     string `json:"policy"`
}

func NewSnapshotterClient(sock string) *SnapshotterClient {
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
	return &SnapshotterClient{
		client: client,
	}
}

func (cli *SnapshotterClient) request(method, urlSuffix string, body any) (respBody []byte, err error) {
	var reqBody io.Reader
	if body != nil {
		reqJSON, err := json.Marshal(body)
		if err != nil {
			return nil, errors.Wrap(err, "marshal request body")
		}

		reqBody = bytes.NewBuffer(reqJSON)
	}

	url := fmt.Sprintf("http://unix%s", urlSuffix)
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, errors.Wrap(err, "build request")
	}
	resp, err := cli.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "do request")
	}
	defer resp.Body.Close()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("faild  to do request(%v), got status %s, and resp %s", req, resp.Status, respBody)
	}

	return
}

func (cli *SnapshotterClient) GetNydusDaemonInfos() ([]*DaemonInfoFromSnapshotter, error) {
	body, err := cli.request("GET", "/api/v1/daemons", nil)
	if err != nil {
		return nil, err
	}

	var infos []*DaemonInfoFromSnapshotter
	if err = json.Unmarshal(body, &infos); err != nil {
		return nil, err
	}

	return infos, nil
}

func (cli *SnapshotterClient) Upgrade(req *UpgradeRequest) error {
	_, err := cli.request("PUT", "/api/v1/daemons/upgrade", req)
	return err
}
