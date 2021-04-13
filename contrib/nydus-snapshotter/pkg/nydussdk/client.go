/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydussdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk/model"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/retry"
)

const (
	infoEndpoint   = "/api/v1/daemon"
	mountEndpoint  = "/api/v1/mount"
	metricEndpoint = "/api/v1/metrics"

	defaultHttpClientTimeout = 30 * time.Second
	contentType              = "application/json"
)

type Interface interface {
	CheckStatus() (model.DaemonInfo, error)
	SharedMount(sharedMountPoint, bootstrap, daemonConfig string) error
	Umount(sharedMountPoint string) error
	GetFsMetric(sharedDaemon bool, sid string) (*model.FsMetric, error)
}

type NydusClient struct {
	httpClient *http.Client
}

func NewNydusClient(sock string) (Interface, error) {
	transport, err := buildTransport(sock)
	if err != nil {
		return nil, err
	}
	return &NydusClient{
		httpClient: &http.Client{
			Timeout:   defaultHttpClientTimeout,
			Transport: transport,
		},
	}, nil
}

func (c *NydusClient) CheckStatus() (model.DaemonInfo, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("http://unix%s", infoEndpoint))
	if err != nil {
		return model.DaemonInfo{}, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return model.DaemonInfo{}, err
	}
	var info model.DaemonInfo
	if err = json.Unmarshal(b, &info); err != nil {
		return model.DaemonInfo{}, err
	}
	return info, nil
}

func (c *NydusClient) Umount(sharedMountPoint string) error {
	requestURL := fmt.Sprintf("http://unix%s?mountpoint=%s", mountEndpoint, sharedMountPoint)
	req, err := http.NewRequest(http.MethodDelete, requestURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return handleMountError(resp.Body)
}

func (c *NydusClient) GetFsMetric(sharedDaemon bool, sid string) (*model.FsMetric, error) {
	var getStatURL string

	if sharedDaemon {
		getStatURL = fmt.Sprintf("http://unix%s?id=/%s/fs", metricEndpoint, sid)
	} else {
		getStatURL = fmt.Sprintf("http://unix%s", metricEndpoint)
	}

	req, err := http.NewRequest(http.MethodGet, getStatURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, err
	}

	var m model.FsMetric
	if err = json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *NydusClient) SharedMount(sharedMountPoint, bootstrap, daemonConfig string) error {
	requestURL := fmt.Sprintf("http://unix%s?mountpoint=%s", mountEndpoint, sharedMountPoint)
	content, err := ioutil.ReadFile(daemonConfig)
	if err != nil {
		return errors.Wrapf(err, "failed to get content of daemon config %s", daemonConfig)
	}
	body, err := json.Marshal(model.NewMountRequest(bootstrap, string(content)))
	if err != nil {
		return errors.Wrap(err, "failed to create mount request")
	}
	resp, err := c.httpClient.Post(requestURL, contentType, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return handleMountError(resp.Body)
}

func waitUntilSocketReady(sock string) error {
	return retry.Do(func() error {
		if _, err := os.Stat(sock); err != nil {
			return err
		}
		return nil
	},
		retry.Attempts(3),
		retry.LastErrorOnly(true),
		retry.Delay(100*time.Millisecond))
}

func buildTransport(sock string) (http.RoundTripper, error) {
	err := waitUntilSocketReady(sock)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		// DisableKeepAlives:     true,
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
	}, nil
}
func handleMountError(r io.Reader) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	var errMessage model.ErrorMessage
	if err = json.Unmarshal(b, &errMessage); err != nil {
		return err
	}
	return errors.New(errMessage.Message)
}
