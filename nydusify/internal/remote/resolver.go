/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/pkg/errors"
)

// CredentialFunc accepts a registry host and returns the username and password
// to authenticate with it.
type CredentialFunc = func(host string) (string, string, error)

func newHTTPClient(skipTLSVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
}

// stallTimeout is how long a registry or token server may send nothing, while
// the response headers or more of a response body are awaited, before the
// request is given up. It is the image pull progress timeout of containerd's
// CRI plugin.
var stallTimeout = 5 * time.Minute

// stallError reports a request given up for a server that sent nothing. It is
// a timeout to the retries, unlike the canceled context it replaces.
type stallError struct{ timeout time.Duration }

func (e stallError) Error() string   { return "server sent nothing for " + e.timeout.String() }
func (e stallError) Timeout() bool   { return true }
func (e stallError) Temporary() bool { return true }

// stallTransport gives up a request whose response headers, or whose next
// bytes of the response body, do not arrive within timeout. The time the
// caller takes between two reads does not count, so the whole transfer has no
// limit. Unless everyMethod is set only GET and HEAD are watched: a registry
// may take minutes to answer the PUT that commits a large blob.
type stallTransport struct {
	base        http.RoundTripper
	timeout     time.Duration
	everyMethod bool
}

func (t stallTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.everyMethod && req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	stalled := &atomic.Bool{}
	timer := time.AfterFunc(t.timeout, func() {
		stalled.Store(true)
		cancel()
	})
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	timer.Stop()
	if err != nil {
		cancel()
		if stalled.Load() {
			err = stallError{t.timeout}
		}
		return nil, err
	}
	resp.Body = &stallBody{ReadCloser: resp.Body, timeout: t.timeout, timer: timer, stalled: stalled, cancel: cancel}
	return resp, nil
}

// stallBody is a response body that arms the timer of its request around each
// read.
type stallBody struct {
	io.ReadCloser
	timeout time.Duration
	timer   *time.Timer
	stalled *atomic.Bool
	cancel  context.CancelFunc
}

func (b *stallBody) Read(data []byte) (int, error) {
	b.timer.Reset(b.timeout)
	read, err := b.ReadCloser.Read(data)
	b.timer.Stop()
	if err != nil && err != io.EOF && b.stalled.Load() {
		err = stallError{b.timeout}
	}
	return read, err
}

func (b *stallBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// transientStatusTransport returns a GET or HEAD the registry answers with a
// transient status as the typed error of that status. Containerd's fetcher
// reports such an answer as an untyped error, which the pull retries could not
// tell from a definitive one.
type transientStatusTransport struct{ http.RoundTripper }

func (t transientStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) ||
		!isTransientPushError(remoteserrors.ErrUnexpectedStatus{StatusCode: resp.StatusCode}) {
		return resp, err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil, remoteserrors.NewUnexpectedStatusErr(resp)
}

// newRegistryClient builds the client of registry requests, routing manifest
// and blob GETs through Dragonfly when it is enabled.
func newRegistryClient(skipTLSVerify bool) *http.Client {
	client := newHTTPClient(skipTLSVerify)
	client.Transport = transientStatusTransport{stallTransport{base: client.Transport, timeout: stallTimeout}}
	if dragonflyProxy != nil {
		client.Transport = &dragonflyTransport{base: client.Transport, getter: dragonflyProxy}
	}
	return client
}

// NewDockerConfigCredFunc reads the docker auth config file
// (`$DOCKER_CONFIG/config.json`, defaulting to `~/.docker`) to resolve
// credentials for a registry host.
func NewDockerConfigCredFunc() CredentialFunc {
	return func(host string) (string, string, error) {
		// Docker Hub auth is stored under the legacy v1 key.
		if host == "registry-1.docker.io" {
			host = "https://index.docker.io/v1/"
		}
		config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
		authConfig, err := config.GetAuthConfig(host)
		if err != nil {
			return "", "", errors.Wrapf(err, "get auth config for %q", host)
		}
		return authConfig.Username, authConfig.Password, nil
	}
}

// NewResolver builds a docker registry resolver that handles authentication,
// optional TLS verification skipping, and optional plain HTTP.
func NewResolver(insecure, plainHTTP bool, credFunc CredentialFunc) remotes.Resolver {
	return newResolver(insecure, plainHTTP, credFunc, newRegistryClient(insecure))
}

func newResolver(insecure, plainHTTP bool, credFunc CredentialFunc, client *http.Client) remotes.Resolver {
	// A token request is small whatever its method, so all of them are watched.
	authClient := newHTTPClient(insecure)
	authClient.Transport = stallTransport{base: authClient.Transport, timeout: stallTimeout, everyMethod: true}
	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(authClient),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(client),
		docker.WithPlainHTTP(func(_ string) (bool, error) {
			return plainHTTP, nil
		}),
	)
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})
}
