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
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/nydussdk/model"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/utils/retry"
)

const (
	infoEndpoint  = "/api/v1/daemon"
	mountEndpoint = "/api/v1/mount"

	defaultHttpClientTimeout = 30 * time.Second
	contentType              = "application/json"
)

type Interface interface {
	CheckStatus() (model.DaemonInfo, error)
	SharedMount(sharedMountPoint, bootstrap, daemonConfig string) error
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

func (c *NydusClient) SharedMount(sharedMountPoint, bootstrap, daemonConfig string) error {
	requestURl := fmt.Sprintf("http://unix%s?mountpoint=%s", mountEndpoint, sharedMountPoint)
	content, err := ioutil.ReadFile(daemonConfig)
	if err != nil {
		return errors.Wrapf(err, "failed to get content of daemon config %s", daemonConfig)
	}
	body, err := json.Marshal(model.NewMountRequest(bootstrap, string(content)))
	if err != nil {
		return errors.Wrap(err, "failed to create mount request")
	}
	resp, err := c.httpClient.Post(requestURl, contentType, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var errMessage model.ErrorMessage
	if err = json.Unmarshal(b, &errMessage); err != nil {
		return err
	}
	return errors.New(errMessage.Message)
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
