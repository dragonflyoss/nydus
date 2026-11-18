/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/client_mock.go -source client.go -package mocks

// Package nydusd talks to nydus daemons over their API socket.
package nydusd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const (
	// endpointMetrics answers 200 once the daemon serves requests.
	endpointMetrics = "/metrics"

	// endpointDaemon describes the daemon. The path carries the API version,
	// so a daemon of another API version answers it with 404.
	endpointDaemon = "/api/v1/daemon"

	// endpointBackendAuthBasic replaces the registry backend's basic
	// credentials.
	endpointBackendAuthBasic = "/api/v1/backend/auth/basic"

	// CapabilityBackendAuthBasic is the capability of a daemon whose basic
	// credentials UpdateAuth can replace.
	CapabilityBackendAuthBasic = "backend_auth_basic"

	// requestTimeout bounds one API request.
	requestTimeout = 5 * time.Second

	// maxErrorBody bounds how much of an error answer is read.
	maxErrorBody = 4096

	// maxMetricsBody bounds how much of the metrics is read.
	maxMetricsBody = 8 << 20

	// maxInfoBody bounds how much of the daemon's description is read.
	maxInfoBody = 64 << 10
)

// Info describes a daemon, the answer of GET /api/v1/daemon. The daemon only
// ever adds fields and capabilities, so unknown ones are ignored.
type Info struct {
	// Version is the nydus version of the daemon.
	Version string `json:"version"`

	// GitCommit is the git commit the daemon was built from.
	GitCommit string `json:"git_commit"`

	// PID is the process ID of the daemon.
	PID int `json:"pid"`

	// Capabilities are the optional calls the daemon serves. A caller gates
	// such a call on its capability, never on Version, as a CSI driver's
	// capabilities are read, refer to
	// https://github.com/container-storage-interface/spec/blob/master/spec.md.
	Capabilities []string `json:"capabilities"`
}

// Client talks to a nydus daemon's API server over its unix socket.
type Client interface {
	// Info returns the daemon's build, process and capabilities.
	// errdefs.ErrNotImplemented means the daemon does not serve this API
	// version.
	Info(ctx context.Context) (*Info, error)

	// Ready returns nil once the daemon answers GET /metrics with 200.
	Ready(ctx context.Context) error

	// Metrics returns the daemon's Prometheus metric families by name.
	Metrics(ctx context.Context) (map[string]*dto.MetricFamily, error)

	// UpdateAuth replaces the registry backend's basic credentials with
	// auth, the base64 username:password a daemon config carries.
	// errdefs.ErrNotImplemented means the daemon has no such route or no
	// registry backend.
	UpdateAuth(ctx context.Context, auth string) error
}

// client is the HTTP over unix socket Client.
type client struct {
	// http is the client dialing the daemon socket.
	http *http.Client
}

// NewClient returns a client of the daemon API listening on socket.
func NewClient(socket string) Client {
	dialer := &net.Dialer{}
	return &client{
		http: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Info returns the daemon's build, process and capabilities.
// errdefs.ErrNotImplemented means the daemon does not serve this API version.
func (c *client) Info(ctx context.Context) (*Info, error) {
	var info Info
	if err := c.do(ctx, http.MethodGet, endpointDaemon, nil, http.StatusOK, func(body io.Reader) error {
		return json.NewDecoder(io.LimitReader(body, maxInfoBody)).Decode(&info)
	}); err != nil {
		return nil, err
	}

	return &info, nil
}

// Ready returns nil once the daemon answers GET /metrics with 200.
func (c *client) Ready(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, endpointMetrics, nil, http.StatusOK, nil)
}

// Metrics returns the daemon's Prometheus metric families by name.
func (c *client) Metrics(ctx context.Context) (map[string]*dto.MetricFamily, error) {
	var families map[string]*dto.MetricFamily
	if err := c.do(ctx, http.MethodGet, endpointMetrics, nil, http.StatusOK, func(body io.Reader) error {
		parser := expfmt.NewTextParser(model.UTF8Validation)
		var err error
		families, err = parser.TextToMetricFamilies(io.LimitReader(body, maxMetricsBody))
		return err
	}); err != nil {
		return nil, err
	}

	return families, nil
}

// UpdateAuth replaces the registry backend's basic credentials with auth,
// the base64 username:password a daemon config carries.
// errdefs.ErrNotImplemented means the daemon has no such route or no
// registry backend.
func (c *client) UpdateAuth(ctx context.Context, auth string) error {
	// The API takes the user name and the password apart, as the Docker
	// Engine API does.
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return fmt.Errorf("decode auth: %w: %w", err, errdefs.ErrInvalidArgument)
	}

	username, password, _ := strings.Cut(string(decoded), ":")
	body, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: username, Password: password})
	if err != nil {
		return err
	}

	return c.do(ctx, http.MethodPut, endpointBackendAuthBasic, body, http.StatusNoContent, nil)
}

// do sends a request, checks the answer's status and, when read is given,
// hands it the body of an answer with the wanted status.
func (c *client) do(ctx context.Context, method, path string, body []byte, want int, read func(body io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://nydusd"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == want {
		if read == nil {
			return nil
		}

		if err := read(resp.Body); err != nil {
			return fmt.Errorf("%s %s: read answer: %w", method, path, err)
		}

		return nil
	}

	var answer struct {
		Message string `json:"message"`
	}
	// A body that fails to read still leaves the status to report.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if json.Unmarshal(data, &answer) != nil || answer.Message == "" {
		answer.Message = string(bytes.TrimSpace(data))
	}

	err = fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, answer.Message)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", err, errdefs.ErrNotImplemented)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %w", err, errdefs.ErrInvalidArgument)
	case http.StatusForbidden:
		return fmt.Errorf("%w: %w", err, errdefs.ErrPermissionDenied)
	default:
		return err
	}
}
