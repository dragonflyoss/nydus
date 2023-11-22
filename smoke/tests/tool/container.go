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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ContainerMetrics struct {
	ReadCount       uint64 `json:"read_count"`
	ReadAmountTotal uint64 `json:"read_amount_total"`
}

type RunArgs struct {
	WaitURL            string
	BaselineReadCount  map[string]uint64
	BaselineReadAmount map[string]uint64
}

var URL_WAIT = map[string]RunArgs{
	"wordpress": {
		WaitURL: "http://localhost:80",
		BaselineReadCount: map[string]uint64{
			"fs-version-5": 328,
			"fs-version-6": 131,
			"zran":         186,
		},
		BaselineReadAmount: map[string]uint64{
			"fs-version-5": 54307819,
			"fs-version-6": 77580818,
			"zran":         79836339,
		},
	},
}

var supportContainerImages = []string{"wordpress"}

// SupportContainerImage help to check if we support the image or not
func SupportContainerImage(image string) bool {
	return contains(supportContainerImages, image)
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if strings.Contains(v, value) {
			return true
		}
	}
	return false
}

// runUrlWaitContainer run Contaienr util geting http response from WaitUrl
func runUrlWaitContainer(t *testing.T, image string, containerName string, runArgs RunArgs) {
	cmd := fmt.Sprintf("sudo nerdctl --insecure-registry --snapshotter nydus run -d --net=host --name=%s %s", containerName, image)
	RunWithoutOutput(t, cmd)
	for {
		resp, err := http.Get(runArgs.WaitURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// RunContainer and get metrics from api socket.
// Test will fail if performance below baseline.
func RunContainer(t *testing.T, image string, containerName string, mode string) {
	args, ok := URL_WAIT[ImageRepo(t, image)]
	if ok {
		runUrlWaitContainer(t, image, containerName, args)
	}
	containerMetrics, err := getContainerMetrics(t)
	if err != nil {
		t.Logf(err.Error())
	}
	if containerMetrics.ReadAmountTotal > uint64(float64(args.BaselineReadAmount[mode])*1.05) ||
		containerMetrics.ReadCount > uint64(float64(args.BaselineReadCount[mode])*1.05) {
		t.Fatalf(fmt.Sprintf("Performance reduction with ReadAmount %d and ReadCount %d", containerMetrics.ReadAmountTotal, containerMetrics.ReadCount))
	}
	t.Logf(fmt.Sprintf("Performance Test: ReadAmount %d and ReadCount %d", containerMetrics.ReadAmountTotal, containerMetrics.ReadCount))
}

// getContainerMetrics get metrics by nydus api sock
func getContainerMetrics(t *testing.T) (*ContainerMetrics, error) {
	transport := &http.Transport{
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}
			return dialer.DialContext(ctx, "unix", searchAPISockPath(t))
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get("http://unix/api/v1/metrics/backend")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info ContainerMetrics
	if err = json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// searchAPISockPath search sock filepath in nydusd work dir, default in "/var/lib/containerd-nydus/socket"
func searchAPISockPath(t *testing.T) string {
	var apiSockPath string

	err := filepath.Walk("/var/lib/containerd-nydus/socket", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() != "socket" {
			apiSockPath = path
			return filepath.SkipDir
		}
		return nil
	})
	require.NoError(t, err)

	return apiSockPath + "/api.sock"
}
