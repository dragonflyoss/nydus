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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/containerd/errdefs"
)

const (
	// endpointMetrics answers 200 once the daemon serves requests.
	endpointMetrics = "/metrics"

	// endpointBackendAuth replaces the registry credential.
	endpointBackendAuth = "/api/v1/backend/auth"

	// defaultRequestTimeout bounds one API request.
	defaultRequestTimeout = 5 * time.Second

	// maxErrorBody bounds how much of an answer is read.
	maxErrorBody = 4096
)

// Client talks to a nydus daemon's API server over its unix socket.
type Client interface {
	// Ready returns nil once the daemon answers GET /metrics with 200.
	Ready(ctx context.Context) error

	// UpdateAuth replaces the registry backend's credential, a base64
	// username:password. errdefs.ErrNotImplemented means the daemon has no
	// such route or no registry backend.
	UpdateAuth(ctx context.Context, auth string) error
}

// client is the HTTP over unix socket Client.
type client struct {
	// http is the client dialing the daemon socket.
	http *http.Client
}

// NewClient returns a new daemon API client interface of a socket.
func NewClient(socket string) Client {
	dialer := &net.Dialer{}
	return &client{
		http: &http.Client{
			Timeout: defaultRequestTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// Ready returns nil once the daemon answers GET /metrics with 200.
func (c *client) Ready(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, endpointMetrics, nil, http.StatusOK)
}

// UpdateAuth replaces the registry backend's credential, a base64
// username:password. errdefs.ErrNotImplemented means the daemon has no such
// route or no registry backend.
func (c *client) UpdateAuth(ctx context.Context, auth string) error {
	body, err := json.Marshal(struct {
		Auth string `json:"auth"`
	}{Auth: auth})
	if err != nil {
		return err
	}

	return c.do(ctx, http.MethodPut, endpointBackendAuth, body, http.StatusNoContent)
}

// do sends a request and checks the answer's status.
func (c *client) do(ctx context.Context, method, path string, body []byte, want int) error {
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
		// Drain the body so the answer is fully read before the connection
		// closes, bounded as the error body is.
		_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		return err
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
