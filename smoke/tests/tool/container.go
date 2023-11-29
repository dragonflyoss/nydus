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
	E2ETime         time.Duration `json:"e2e_time"`
	ReadCount       uint64        `json:"read_count"`
	ReadAmountTotal uint64        `json:"read_amount_total"`
	ImageSize       int64         `json:"image_size"`
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

// RunContainerWithBaseline and get metrics from api socket.
// Test will fail if performance below baseline.
func RunContainerWithBaseline(t *testing.T, image string, containerName string, mode string) {
	args, ok := URL_WAIT[ImageRepo(t, image)]
	if ok {
		runUrlWaitContainer(t, image, containerName, args)
		defer clearContainer(t, image, containerName)
	} else {
		t.Fatalf(fmt.Sprintf("%s is not in URL_WAIT", image))
	}
	backendMetrics, err := getContainerBackendMetrics(t)
	if err != nil {
		t.Logf(err.Error())
	}
	if backendMetrics.ReadAmountTotal > uint64(float64(args.BaselineReadAmount[mode])*1.05) ||
		backendMetrics.ReadCount > uint64(float64(args.BaselineReadCount[mode])*1.05) {
		t.Fatalf(fmt.Sprintf("Performance reduction with ReadAmount %d and ReadCount %d", backendMetrics.ReadAmountTotal, backendMetrics.ReadCount))
	}
	t.Logf(fmt.Sprintf("Performance Test: ReadAmount %d and ReadCount %d", backendMetrics.ReadAmountTotal, backendMetrics.ReadCount))
}

// RunContainer and return container metric
func RunContainer(t *testing.T, image string, containerName string) *ContainerMetrics {
	var containerMetic ContainerMetrics
	args, ok := URL_WAIT[ImageRepo(t, image)]
	if ok {
		startTime := time.Now()
		runUrlWaitContainer(t, image, containerName, args)
		endTime := time.Now()
		containerMetic.E2ETime = endTime.Sub(startTime)
		defer clearContainer(t, image, containerName)
	}
	backendMetrics, err := getContainerBackendMetrics(t)
	if err != nil {
		t.Logf(err.Error())
	}
	containerMetic.ReadAmountTotal = backendMetrics.ReadAmountTotal
	containerMetic.ReadCount = backendMetrics.ReadCount
	return &containerMetic
}

// ClearContainer clear container by containerName
func clearContainer(t *testing.T, image string, containerName string) {
	RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter nydus rm -f %s", containerName))
	RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter nydus image rm %s", image))
}

// getContainerBackendMetrics get backend metrics by nydus api sock
func getContainerBackendMetrics(t *testing.T) (*ContainerMetrics, error) {
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
