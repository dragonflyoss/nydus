/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"context"
	"net/http"
	"regexp"
	"strconv"

	request "d7y.io/dragonfly-sdk/client-request/go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// getter is the subset of the Dragonfly SDK proxy the transport needs.
type getter interface {
	Get(ctx context.Context, req *request.GetRequest) (*request.GetResponse, error)
}

var (
	dragonflyEndpoint string
	dragonflyProxy    getter
)

// EnableDragonfly routes the registry manifest and blob GETs of every
// resolver built afterwards through the Dragonfly scheduler at endpoint. The
// returned function releases the SDK proxy. An empty endpoint disables it.
func EnableDragonfly(ctx context.Context, endpoint string) (func(), error) {
	if endpoint == "" {
		return func() {}, nil
	}
	proxy, err := request.New(ctx, endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "connect dragonfly scheduler %q", endpoint)
	}
	dragonflyEndpoint, dragonflyProxy = endpoint, proxy
	return func() {
		dragonflyEndpoint, dragonflyProxy = "", nil
		_ = proxy.Close()
	}, nil
}

// DragonflyEndpoint returns the scheduler endpoint set by EnableDragonfly, or
// an empty string when Dragonfly is disabled.
func DragonflyEndpoint() string {
	return dragonflyEndpoint
}

var (
	dragonflyPathRe = regexp.MustCompile(`^/v2/.+/(manifests|blobs)/[^/]+$`)
	// manifestDigestRe matches a manifest addressed by digest, whose content
	// is immutable and therefore safe to look up through the seed peers.
	manifestDigestRe = regexp.MustCompile(`^/v2/.+/manifests/([A-Za-z0-9_+.-]+:[A-Za-z0-9=_-]+)$`)
)

// dragonflyTransport sends registry manifest and blob GETs through the
// Dragonfly seed peers and everything else straight to the origin.
type dragonflyTransport struct {
	base   http.RoundTripper
	getter getter
}

// headViaGet answers the HEAD containerd sends to resolve a manifest by
// digest with a Dragonfly GET, so no request reaches the origin. Only the
// response headers are used: the body is closed unread, and the later fetch of
// the manifest is served by the seed peer. It returns nil, leaving the HEAD to
// the origin, for any other request or when the headers cannot describe the
// manifest.
func (t *dragonflyTransport) headViaGet(req *http.Request) *http.Response {
	m := manifestDigestRe.FindStringSubmatch(req.URL.Path)
	if m == nil {
		return nil
	}
	resp, err := t.getter.Get(req.Context(), request.NewGetRequest(
		req.URL.String(), request.WithGetRequestHeader(req.Header)))
	if err != nil {
		return nil
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") == "" {
		return nil
	}
	header := resp.Header.Clone()
	if header.Get("Docker-Content-Digest") == "" {
		header.Set("Docker-Content-Digest", m[1])
	}
	return &http.Response{
		Status:        http.StatusText(http.StatusOK),
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          http.NoBody,
		ContentLength: size,
		Request:       req,
	}
}

// RoundTrip serves a manifest or blob GET from Dragonfly. Any SDK failure
// falls back to the origin, which then gives the authoritative answer, e.g.
// the 401 auth challenge the registry client handles as usual.
func (t *dragonflyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodHead {
		if resp := t.headViaGet(req); resp != nil {
			return resp, nil
		}
		return t.base.RoundTrip(req)
	}
	if req.Method != http.MethodGet || !dragonflyPathRe.MatchString(req.URL.Path) {
		return t.base.RoundTrip(req)
	}

	resp, err := t.getter.Get(req.Context(), request.NewGetRequest(
		req.URL.String(), request.WithGetRequestHeader(req.Header)))
	if err != nil {
		logrus.WithError(err).Warnf("dragonfly GET %s failed, falling back to the origin", req.URL)
		return t.base.RoundTrip(req)
	}
	return &http.Response{
		Status:        http.StatusText(resp.StatusCode),
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        resp.Header,
		Body:          resp.Body,
		ContentLength: -1,
		Request:       req,
	}, nil
}
