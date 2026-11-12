/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	commonv2 "d7y.io/api/v2/pkg/apis/common/v2"
	request "d7y.io/dragonfly-sdk/client-request/go"
	"github.com/cenkalti/backoff/v5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// getter is the subset of the Dragonfly SDK proxy the transport needs.
type getter interface {
	Get(ctx context.Context, req *request.GetRequest) (*request.GetResponse, error)
}

// The SDK is used as nydus fuse's on-demand reads use it (nydus-backend's
// registry/dragonfly.rs): requests are sent at Level6, the SDK's default
// priority, and a transient failure is retried once on the next seed peer
// after a jittered exponential backoff. The per-attempt timeout stays at the
// SDK default of ten minutes, since a request here fetches a whole layer
// rather than one chunk group.
const (
	dragonflyPriority   = int32(commonv2.Priority_LEVEL6)
	dragonflyMaxRetries = 1
)

var (
	dragonflyEndpoint string
	dragonflyProxy    getter
)

// EnableDragonfly routes the registry manifest and blob GETs of every
// resolver built afterwards through the Dragonfly scheduler at endpoint. The
// returned function releases the SDK proxy. An empty endpoint disables it.
//
// A scheduler that cannot be reached is not an error: the requests of this
// process go to the origin, as the reads of a nydus daemon do, and the
// endpoint is still reported to the daemons, which keep trying it.
func EnableDragonfly(ctx context.Context, endpoint string) (func(), error) {
	if endpoint == "" {
		return func() {}, nil
	}
	proxy, err := request.New(ctx, endpoint,
		request.WithProxyMaxRetries(dragonflyMaxRetries),
		request.WithProxyBackoff(backoff.NewExponentialBackOff()),
	)
	if errors.Is(err, request.ErrInvalidArgument) {
		return nil, errors.Wrapf(err, "connect dragonfly scheduler %q", endpoint)
	}
	dragonflyEndpoint = endpoint
	if err != nil {
		logrus.Warnf("dragonfly scheduler %q is unreachable, falling back to the origin: %v", endpoint, err)
		return func() { dragonflyEndpoint = "" }, nil
	}
	dragonflyProxy = proxy
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

// newResponse builds the response of req from a Dragonfly answer.
func newResponse(req *http.Request, status int, header http.Header, body io.ReadCloser, length int64) *http.Response {
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          body,
		ContentLength: length,
		Request:       req,
	}
}

// get fetches the URL of req through the seed peers. A 2xx answer, and an
// error carrying a definitive HTTP status, are returned as a response so the
// registry client settles it as usual, e.g. a 401 auth challenge or a 404. Any
// other failure is returned as an error and sends the caller back to the
// origin: a timeout, a connection failure, or a 5xx, 408 or 429.
func (t *dragonflyTransport) get(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.getter.Get(req.Context(), request.NewGetRequest(req.URL.String(),
		request.WithGetRequestHeader(req.Header),
		request.WithGetRequestPriority(dragonflyPriority),
	))
	var out *http.Response
	if err == nil {
		out = newResponse(req, resp.StatusCode, resp.Header, resp.Body, -1)
	} else if status, header, message, ok := definitiveAnswer(err); ok {
		out, err = newResponse(req, status, header, io.NopCloser(bytes.NewReader(message)), int64(len(message))), nil
	}

	if err != nil {
		logrus.Debugf("GET %s through dragonfly failed in %v: %v", req.URL, time.Since(start), err)
		return nil, err
	}
	logrus.Debugf("GET %s through dragonfly returned %d in %v", req.URL, out.StatusCode, time.Since(start))
	return out, nil
}

// definitiveAnswer extracts the HTTP answer of an SDK error, unless it marks
// a transient failure (5xx, 408, 429) or carries no status at all.
func definitiveAnswer(err error) (status int, header http.Header, message []byte, ok bool) {
	var (
		backend  *request.BackendError
		proxy    *request.ProxyError
		dfdaemon *request.DfdaemonError
	)
	switch {
	case errors.As(err, &backend):
		status, header, message = backend.StatusCode, backend.Header, []byte(backend.Message)
	case errors.As(err, &proxy):
		status, header, message = proxy.StatusCode, proxy.Header, []byte(proxy.Message)
	case errors.As(err, &dfdaemon):
		status, header, message = dfdaemon.StatusCode, dfdaemon.Header, []byte(dfdaemon.Message)
	default:
		return 0, nil, nil, false
	}
	if status >= http.StatusInternalServerError || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return 0, nil, nil, false
	}
	return status, header, message, true
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
	resp, err := t.get(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A definitive answer such as the 401 auth challenge needs no body.
		return newResponse(req, resp.StatusCode, resp.Header, http.NoBody, 0)
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 || resp.Header.Get("Content-Type") == "" {
		return nil
	}
	header := resp.Header.Clone()
	if header.Get("Docker-Content-Digest") == "" {
		header.Set("Docker-Content-Digest", m[1])
	}
	return newResponse(req, http.StatusOK, header, http.NoBody, size)
}

// RoundTrip serves a manifest or blob GET from Dragonfly, falling back to the
// origin when the seed peers cannot serve it.
func (t *dragonflyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch {
	case req.Method == http.MethodHead:
		if resp := t.headViaGet(req); resp != nil {
			return resp, nil
		}
	case req.Method == http.MethodGet && dragonflyPathRe.MatchString(req.URL.Path):
		resp, err := t.get(req)
		if err == nil {
			return resp, nil
		}
		logrus.WithError(err).Warnf("dragonfly request failed, falling back to the origin: GET %s", req.URL)
	}
	return t.base.RoundTrip(req)
}
