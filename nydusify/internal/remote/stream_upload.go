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
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/remotes/docker"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
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
	ctx          context.Context
	host         docker.RegistryHost
	location     *url.URL
	blobsURL     url.URL
	buffer       []byte
	chunkSize    int
	minChunkSize int
	offset       int64
	digester     hash.Hash
	size         int64
	failed       error
	finished     bool
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
		ctx:       ctx,
		host:      host,
		location:  start,
		blobsURL:  url.URL{Scheme: host.Scheme, Host: host.Host, Path: path.Join(host.Path, repository, "blobs")},
		chunkSize: streamUploadChunkSize,
		digester:  sha256.New(),
	}
	resp, err := upload.request(http.MethodPost, start, nil, http.StatusAccepted, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := upload.advance(resp); err != nil {
		return nil, err
	}
	if minimum := resp.Header.Get("OCI-Chunk-Min-Length"); minimum != "" {
		size, err := strconv.ParseUint(minimum, 10, 32)
		if err != nil || size == 0 || size > 64<<20 {
			upload.Abort()
			return nil, fmt.Errorf("unsupported registry minimum chunk size")
		}
		upload.minChunkSize = int(size)
		upload.chunkSize = max(upload.chunkSize, upload.minChunkSize)
	}
	upload.buffer = make([]byte, 0, upload.chunkSize)
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
		n := u.chunkSize - len(u.buffer)
		if n > len(p) {
			n = len(p)
		}
		u.buffer = append(u.buffer, p[:n]...)
		_, _ = u.digester.Write(p[:n])
		u.size += int64(n)
		written += n
		p = p[n:]
		if len(u.buffer) == u.chunkSize {
			if err := u.flush(); err != nil {
				u.failed = err
				return written, err
			}
		}
	}
	return written, nil
}

func (u *BlobStreamUpload) flush() error {
	if len(u.buffer) == 0 || len(u.buffer) < u.minChunkSize {
		return nil
	}
	start, end := u.offset, u.offset+int64(len(u.buffer))
	recoverOffset := false
	probeEmptyRange := true
	var last error
	for attempt := 0; attempt < pushRetries; attempt++ {
		if attempt > 0 {
			if err := u.waitRetry(attempt); err != nil {
				return err
			}
		}
		if recoverOffset {
			if err := u.resumeOffset(end, probeEmptyRange); err != nil {
				if !isTransientPushError(err) {
					return err
				}
				last = err
				continue
			}
		}
		if u.offset == end {
			u.buffer = u.buffer[:0]
			return nil
		}
		payload := u.buffer[u.offset-start:]
		if len(payload) < u.minChunkSize {
			// Coalesce the remaining bytes with the next write, or send
			// them in the final PUT. Never PATCH an undersized slice.
			u.buffer = u.buffer[:copy(u.buffer, payload)]
			return nil
		}
		// Let the registry reject an ambiguous offset before we send the
		// body; the first byte may already have been acknowledged.
		expectContinue := recoverOffset && u.offset == 0 && probeEmptyRange
		resp, err := u.request(http.MethodPatch, u.location, payload, http.StatusAccepted, expectContinue)
		if err == nil {
			err = u.advance(resp)
			if err == nil && resp.Header.Get("Range") != "" {
				var offset int64
				offset, err = uploadOffset(resp.Header.Get("Range"))
				if err == nil && offset != end {
					err = fmt.Errorf("registry acknowledged incomplete chunk")
				}
			}
			_ = resp.Body.Close()
			if err != nil {
				return err
			}
			u.offset = end
			u.buffer = u.buffer[:0]
			return nil
		}
		var status remoteserrors.ErrUnexpectedStatus
		if errors.As(err, &status) && status.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			probeEmptyRange = false
		}
		if !isTransientPushError(err) && !(errors.As(err, &status) && status.StatusCode == http.StatusRequestedRangeNotSatisfiable) {
			return err
		}
		last, recoverOffset = err, true
	}
	return last
}

func (u *BlobStreamUpload) resumeOffset(end int64, tryZero bool) error {
	resp, err := u.request(http.MethodGet, u.location, nil, http.StatusNoContent, false)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := u.advance(resp); err != nil {
		return err
	}
	offset, err := uploadOffset(resp.Header.Get("Range"))
	if err != nil {
		return err
	}
	// Registries can return 0-0 both before and after accepting the first
	// byte. Try zero until a Content-Range starting there is rejected.
	if offset == 1 && u.offset == 0 && tryZero {
		offset = 0
	}
	if offset < u.offset || offset > end {
		return fmt.Errorf("registry upload offset outside buffered chunk")
	}
	u.offset = offset
	return nil
}

func uploadOffset(value string) (int64, error) {
	first, last, ok := strings.Cut(value, "-")
	end, err := strconv.ParseInt(last, 10, 64)
	if !ok || first != "0" || err != nil || end < 0 || end == int64(^uint64(0)>>1) {
		return 0, fmt.Errorf("invalid registry upload Range")
	}
	return end + 1, nil
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
	if err := u.commit(dgst); err != nil {
		u.failed = err
		return ocispec.Descriptor{}, err
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

func (u *BlobStreamUpload) waitRetry(attempt int) error {
	timer := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-u.ctx.Done():
		return u.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (u *BlobStreamUpload) commit(dgst digest.Digest) error {
	blobURL := u.blobsURL
	blobURL.Path = path.Join(blobURL.Path, dgst.String())
	start := u.offset
	tryZero := true
	var last error
	for attempt := 0; attempt < pushRetries; attempt++ {
		if attempt > 0 {
			if err := u.waitRetry(attempt); err != nil {
				return err
			}
		}
		if attempt > 0 && u.offset < u.size {
			if err := u.resumeOffset(u.size, tryZero); err != nil {
				if !isTransientPushError(err) {
					return errors.Join(last, err)
				}
				last = err
				continue
			}
		}
		finishURL := *u.location
		query := finishURL.Query()
		query.Set("digest", dgst.String())
		finishURL.RawQuery = query.Encode()
		expectContinue := attempt > 0 && u.offset == 0 && tryZero && len(u.buffer) != 0
		resp, err := u.request(http.MethodPut, &finishURL, u.buffer[u.offset-start:], http.StatusCreated, expectContinue)
		if err == nil {
			_ = resp.Body.Close()
			return checkStreamUploadDigest(resp, dgst)
		}
		last = err
		retry := isTransientPushError(err)
		var status remoteserrors.ErrUnexpectedStatus
		if u.offset < u.size && errors.As(err, &status) && status.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			tryZero = false
			continue
		}
		if !retry && !(errors.As(err, &status) && status.StatusCode == http.StatusNotFound) {
			return err
		}
		// A lost response may follow a successful PUT that consumed the
		// session. Check the target repository, not the upload location.
		resp, err = u.request(http.MethodHead, &blobURL, nil, http.StatusOK, false)
		if err == nil {
			_ = resp.Body.Close()
			if resp.ContentLength != u.size {
				return fmt.Errorf("registry blob size %d, expected %d", resp.ContentLength, u.size)
			}
			return checkStreamUploadDigest(resp, dgst)
		}
		switch {
		case errors.As(err, &status) && status.StatusCode == http.StatusNotFound:
			if !retry {
				return last
			}
		case !isTransientPushError(err):
			return errors.Join(last, err)
		}
	}
	return last
}

func checkStreamUploadDigest(resp *http.Response, expected digest.Digest) error {
	if actual := resp.Header.Get("Docker-Content-Digest"); actual != "" && actual != expected.String() {
		return fmt.Errorf("registry committed digest %s, expected %s", actual, expected)
	}
	return nil
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
	resp, err := cleanup.request(http.MethodDelete, u.location, nil, http.StatusNoContent, false)
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

func (u *BlobStreamUpload) request(method string, location *url.URL, body []byte, want int, expectContinue bool) (_ *http.Response, err error) {
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
		if expectContinue {
			req.Header.Set("Expect", "100-continue")
		}
		if method == http.MethodPatch || (method == http.MethodPut && len(body) > 0) {
			req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", u.offset, u.offset+int64(len(body))-1))
		}
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
		// Some Docker-compatible registries acknowledge PATCH with 204;
		// the same Location/Range checks still apply to that response.
		if resp.StatusCode != want && !(method == http.MethodPatch && resp.StatusCode == http.StatusNoContent) {
			message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, remoteserrors.ErrUnexpectedStatus{RequestMethod: method, RequestURL: location.Scheme + "://" + location.Host + location.Path, Status: resp.Status, StatusCode: resp.StatusCode, Body: message}
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
