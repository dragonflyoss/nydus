// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// SnapshotterClient commnicates with nydus-snapshotter via
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

func (cli *SnapshotterClient) GetNydusDaemonInfos() ([]*DaemonInfoFromSnapshotter, error) {
	resp, err := cli.client.Get(fmt.Sprintf("http://unix%s", "/api/v1/daemons"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var infos []*DaemonInfoFromSnapshotter
	if err = json.Unmarshal(body, &infos); err != nil {
		return nil, err
	}

	return infos, nil
}
