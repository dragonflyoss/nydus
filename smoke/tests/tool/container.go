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
	Arg                string
	Mount              mountPath
	BaselineReadCount  map[string]uint64
	BaselineReadAmount map[string]uint64
}

type mountPath struct {
	source string
	target string
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
	"node": {
		WaitURL: "http://localhost:80",
		Arg:     "node /src/index.js",
		Mount: mountPath{
			source: "tests/texture/node",
			target: "/src",
		},
	},
}

var CMD_STDOUT = map[string]RunArgs{
	"golang": {
		Mount: mountPath{
			source: "tests/texture/golang",
			target: "/src",
		},
	},
	"amazoncorretto": {
		Mount: mountPath{
			source: "tests/texture/java",
			target: "/src",
		},
	},
	"ruby": {
		Mount: mountPath{
			source: "tests/texture/ruby",
			target: "/src",
		},
	},
	"python": {
		Mount: mountPath{
			source: "tests/texture/python",
			target: "/src",
		},
	},
}

// SupportContainerImage help to check if we support the image or not
func SupportContainerImage(image string) bool {
	_, existsInUrlWait := URL_WAIT[image]
	_, existsInCmdStdout := CMD_STDOUT[image]
	return existsInUrlWait || existsInCmdStdout
}

// runUrlWaitContainer run container util geting http response from WaitUrl
func runUrlWaitContainer(t *testing.T, image string, snapshotter string, containerName string, runArgs RunArgs) {
	cmd := fmt.Sprintf("sudo nerdctl --insecure-registry --snapshotter %s run -d --net=host", snapshotter)
	if runArgs.Mount.source != "" {
		currentDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("can't get rooted path name")
		}
		cmd += fmt.Sprintf(" --volume %s:%s", filepath.Join(currentDir, runArgs.Mount.source), runArgs.Mount.target)
	}
	cmd += fmt.Sprintf(" --name=%s %s %s", containerName, image, runArgs.Arg)
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

// runCmdStdoutContainer run some commands in container by entrypoint.sh
func runCmdStdoutContainer(t *testing.T, image string, snapshotter string, containerName string, runArgs RunArgs) {
	cmd := fmt.Sprintf("sudo nerdctl --insecure-registry --snapshotter %s run -i --net=host", snapshotter)
	if runArgs.Mount.source != "" {
		currentDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("can't get rooted path name")
		}
		cmd += fmt.Sprintf(" -v %s:%s", filepath.Join(currentDir, runArgs.Mount.source), runArgs.Mount.target)
	}
	cmd += fmt.Sprintf(" --name=%s %s sh /src/entrypoint.sh", containerName, image)
	Run(t, cmd)
}

// RunContainerWithBaseline and get metrics from api socket.
// Test will fail if performance below baseline.
func RunContainerWithBaseline(t *testing.T, image string, containerName string, mode string) {
	args, ok := URL_WAIT[ImageRepo(t, image)]
	if ok {
		runUrlWaitContainer(t, image, "nydus", containerName, args)
		defer clearContainer(t, image, "nydus", containerName)
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
func RunContainer(t *testing.T, image string, snapshotter string, containerName string) *ContainerMetrics {
	var containerMetic ContainerMetrics
	startTime := time.Now()

	// runContainer
	args, ok := URL_WAIT[ImageRepo(t, image)]
	if ok {
		runUrlWaitContainer(t, image, snapshotter, containerName, args)
		defer clearContainer(t, image, snapshotter, containerName)
	} else if args, ok := CMD_STDOUT[ImageRepo(t, image)]; ok {
		runCmdStdoutContainer(t, image, snapshotter, containerName, args)
		defer clearContainer(t, image, snapshotter, containerName)
	}

	containerMetic.E2ETime = time.Since(startTime)
	if snapshotter == "nydus" {
		backendMetrics, err := getContainerBackendMetrics(t)
		if err != nil {
			t.Logf(err.Error())
		}
		containerMetic.ReadAmountTotal = backendMetrics.ReadAmountTotal
		containerMetic.ReadCount = backendMetrics.ReadCount
	}

	return &containerMetic
}

// ClearContainer clear container by containerName
func clearContainer(t *testing.T, image string, snapshotter, containerName string) {
	RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter %s rm -f %s", snapshotter, containerName))
	RunWithoutOutput(t, fmt.Sprintf("sudo nerdctl --snapshotter %s image rm %s", snapshotter, image))
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
