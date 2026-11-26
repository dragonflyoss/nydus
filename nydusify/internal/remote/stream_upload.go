/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

const streamUploadChunkSize = 4 << 20

// BlobStreamUpload uploads a Nydus full blob without a local content-store
// copy. A bounded buffer makes each PATCH replayable while the full stream is
// consumed only once. Finish supplies the digest unknown when POST begins.
type BlobStreamUpload struct {
	ctx      context.Context
	host     docker.RegistryHost
	location *url.URL
	buffer   []byte
	digester hash.Hash
	size     int64
	failed   error
	finished bool
}

func (p *Provider) NewBlobStreamUpload(ctx context.Context, ref string) (*BlobStreamUpload, error) {
	normalized, err := normalizeRef(ref)
	if err != nil {
		return nil, err
	}
	named, err := reference.ParseNormalizedNamed(normalized)
	if err != nil {
		return nil, err
	}
	repository := reference.Path(named)
	hosts, err := newRegistryHosts(p.targetInsecure, p.targetPlainHTTP, p.credFunc)(reference.Domain(named))
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no registry host for %q", ref)
	}
	host := hosts[0]
	ctx = docker.WithScope(ctx, fmt.Sprintf("repository:%s:pull,push", repository))
	start := &url.URL{
		Scheme: host.Scheme,
		Host:   host.Host,
		Path:   path.Join(host.Path, repository, "blobs/uploads") + "/",
	}
	upload := &BlobStreamUpload{
		ctx:      ctx,
		host:     host,
		location: start,
		buffer:   make([]byte, 0, streamUploadChunkSize),
		digester: sha256.New(),
	}
	resp, err := upload.request(http.MethodPost, start, nil, http.StatusAccepted)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := upload.advance(resp); err != nil {
		return nil, err
	}
	return upload, nil
}

func (u *BlobStreamUpload) Write(p []byte) (int, error) {
	if u.finished {
		return 0, fmt.Errorf("blob upload already finished")
	}
	if u.failed != nil {
		return 0, u.failed
	}
	written := 0
	for len(p) > 0 {
		n := streamUploadChunkSize - len(u.buffer)
		if n > len(p) {
			n = len(p)
		}
		u.buffer = append(u.buffer, p[:n]...)
		_, _ = u.digester.Write(p[:n])
		u.size += int64(n)
		written += n
		p = p[n:]
		if len(u.buffer) == streamUploadChunkSize {
			if err := u.flush(); err != nil {
				u.failed = err
				return written, err
			}
		}
	}
	return written, nil
}

func (u *BlobStreamUpload) flush() error {
	if len(u.buffer) == 0 {
		return nil
	}
	resp, err := u.request(http.MethodPatch, u.location, u.buffer, http.StatusAccepted)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := u.advance(resp); err != nil {
		return err
	}
	u.buffer = u.buffer[:0]
	return nil
}

// Finish commits the registry upload and returns its OCI data-layer descriptor.
func (u *BlobStreamUpload) Finish() (ocispec.Descriptor, error) {
	if u.finished || u.failed != nil {
		return ocispec.Descriptor{}, fmt.Errorf("blob upload is not active")
	}
	if err := u.flush(); err != nil {
		u.failed = err
		return ocispec.Descriptor{}, err
	}
	dgst := digest.Digest("sha256:" + hex.EncodeToString(u.digester.Sum(nil)))
	finishURL := *u.location
	query := finishURL.Query()
	query.Set("digest", dgst.String())
	finishURL.RawQuery = query.Encode()
	resp, err := u.request(http.MethodPut, &finishURL, nil, http.StatusCreated)
	if err != nil {
		u.failed = err
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if remoteDigest := resp.Header.Get("Docker-Content-Digest"); remoteDigest != "" && remoteDigest != dgst.String() {
		u.failed = fmt.Errorf("registry committed digest %s, expected %s", remoteDigest, dgst)
		return ocispec.Descriptor{}, u.failed
	}
	u.finished = true
	return ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    dgst,
		Size:      u.size,
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed: dgst.String(),
			nydus.LayerAnnotationNydusBlob:    "true",
		},
	}, nil
}

// Abort removes an unfinished upload session. It is safe to call after Finish.
func (u *BlobStreamUpload) Abort() {
	if u.finished || u.location == nil {
		return
	}
	// Cancellation stops streaming, but cleanup still needs a bounded request.
	cleanup := *u
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.ctx), 5*time.Second)
	defer cancel()
	cleanup.ctx = ctx
	resp, err := cleanup.request(http.MethodDelete, u.location, nil, http.StatusNoContent)
	if err == nil {
		_ = resp.Body.Close()
	}
	u.finished = true
}

func (u *BlobStreamUpload) advance(resp *http.Response) error {
	location := resp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("registry upload response has no Location")
	}
	relative, err := url.Parse(location)
	if err != nil {
		return redactUploadError(err)
	}
	u.location = resp.Request.URL.ResolveReference(relative)
	return nil
}

func (u *BlobStreamUpload) request(method string, location *url.URL, body []byte, want int) (_ *http.Response, err error) {
	defer func() { err = redactUploadError(err) }()
	client := *u.host.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if check := u.host.Client.CheckRedirect; check != nil {
			if err := check(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return fmt.Errorf("too many registry upload redirects")
		}
		if req.URL.Host != u.host.Host || req.URL.Scheme != u.host.Scheme {
			for key := range u.host.Header {
				req.Header.Del(key)
			}
			for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"} {
				req.Header.Del(key)
			}
		}
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(u.ctx, method, location.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		// A registry may redirect an upload to signed object storage. Do
		// not forward credentials or custom headers across host/TLS changes.
		var authorizer docker.Authorizer
		if req.URL.Host == u.host.Host && req.URL.Scheme == u.host.Scheme {
			for key, values := range u.host.Header {
				req.Header[key] = append([]string(nil), values...)
			}
			authorizer = u.host.Authorizer
		}
		if authorizer != nil {
			if err := authorizer.Authorize(u.ctx, req); err != nil {
				return nil, err
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && authorizer != nil {
			if err := authorizer.AddResponses(u.ctx, []*http.Response{resp}); err != nil {
				_ = resp.Body.Close()
				return nil, err
			}
			_ = resp.Body.Close()
			continue
		}
		if resp.StatusCode != want {
			message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("registry %s upload: status %d: %s", method, resp.StatusCode, message)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("registry authentication failed")
}

// Signed upload locations grant access to object storage. Preserve typed
// transport errors and their causes without exposing URL credentials in logs.
func redactUploadError(err error) error {
	var original *url.Error
	if !errors.As(err, &original) {
		return err
	}
	redacted := *original
	location, parseErr := url.Parse(original.URL)
	if parseErr != nil {
		redacted.URL = "<redacted>"
	} else {
		location.User = nil
		location.RawQuery = ""
		location.Fragment = ""
		location.RawFragment = ""
		redacted.URL = location.String()
	}
	redacted.Err = redactUploadError(original.Err)
	return &redacted
}
