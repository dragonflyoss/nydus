/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package remote provides a content store and resolver for pulling and pushing
// images from remote registries.
package remote

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// fetch resolves ref and downloads the image (index/manifests/config and a
// selected subset of layers) for the platforms matched by platformMC into
// store. It returns the resolved root descriptor.
//
// Which data layers are downloaded is controlled by opt: see PullOption.
// Index/manifest/config descriptors and (for nydus images) the bootstrap
// layer are always fetched.
//
// Adapted from containerd's client pull flow.
func fetch(ctx context.Context, store content.Store, resolver remotes.Resolver, ref string, platformMC platforms.MatchComparer, opt PullOption) (ocispec.Descriptor, error) {
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "resolve %q", ref)
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "get fetcher for %q", name)
	}

	if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
		return ocispec.Descriptor{}, errors.Wrap(errdefs.ErrNotImplemented, "docker schema1 manifests are not supported")
	}

	childrenHandler := images.ChildrenHandler(store)
	childrenHandler = images.FilterPlatforms(childrenHandler, platformMC)
	childrenHandler = selectLayersHandler(childrenHandler, opt)

	appendDistSrc, err := docker.AppendDistributionSourceLabel(store, ref)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "build distribution source label handler")
	}

	handler := images.Handlers(
		fetchHandler(store, fetcher),
		childrenHandler,
		appendDistSrc,
	)

	if err := images.Dispatch(ctx, handler, nil, desc); err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "fetch %q", ref)
	}
	return desc, nil
}

// selectLayersHandler wraps h to drop layer descriptors that should not be
// downloaded, so that images.Dispatch never recurses into (and thus never
// fetches) them. Index, manifest and config descriptors are always kept, as is
// the nydus bootstrap layer.
//
// Filtering rules per layer:
//   - nydus bootstrap layer: always kept (needed for the static check and the
//     metadata export);
//   - nydus data blob layer: kept only when opt.PullNydusBlobs is true;
//   - OCI data layer: kept only when opt.PullOCILayers is true.
func selectLayersHandler(h images.HandlerFunc, opt PullOption) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := h(ctx, desc)
		if err != nil {
			return nil, err
		}
		filtered := children[:0]
		for _, child := range children {
			switch {
			case nydus.IsBootstrap(child):
				filtered = append(filtered, child)
			case nydus.IsBlob(child):
				if opt.PullNydusBlobs {
					filtered = append(filtered, child)
				}
			case images.IsLayerType(child.MediaType):
				if opt.PullOCILayers {
					filtered = append(filtered, child)
				}
			default:
				filtered = append(filtered, child)
			}
		}
		return filtered, nil
	}
}

func fetchHandler(ingester content.Ingester, fetcher remotes.Fetcher) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
			return nil, errors.Errorf("%v not supported", desc.MediaType)
		}
		err := remotes.Fetch(ctx, ingester, fetcher, desc)
		if errdefs.IsAlreadyExists(err) {
			return nil, nil
		}
		return nil, err
	}
}

// push uploads desc and all of its content from store to the registry under
// ref.
//
// Adapted from containerd's client push flow.
func push(ctx context.Context, store content.Store, resolver remotes.Resolver, desc ocispec.Descriptor, ref string, platformMC platforms.MatchComparer) error {
	pushRef := ref
	if pushRef == "" {
		return errors.New("empty push reference")
	}
	pusher, err := resolver.Pusher(ctx, pushRef)
	if err != nil {
		return errors.Wrapf(err, "create pusher for %q", pushRef)
	}
	return remotes.PushContent(ctx, &retryPusher{pusher: pusher}, desc, store, nil, platformMC, nil)
}

// pushRetries bounds upload attempts, including containerd's in-session resets.
const pushRetries = 5

// retryPusher deliberately exposes only Pusher, not Ingester: Push can replace
// an incomplete upload, whereas OpenWriter may wait on a stale active tracker.
type retryPusher struct {
	pusher remotes.Pusher
	locks  sync.Map
}

func (pusher *retryPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	entry, _ := pusher.locks.LoadOrStore(remotes.MakeRefKey(ctx, desc), make(chan struct{}, 1))
	lock := entry.(chan struct{})
	select {
	case lock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	writer := &retryPushWriter{pusher: pusher.pusher, ctx: ctx, desc: desc, unlock: func() { <-lock }}
	if err := writer.open(); err != nil {
		_ = writer.Close()
		return nil, err
	}
	return writer, nil
}

// retryPushWriter returns ErrReset after replacing a failed remote writer so
// content.Copy rewinds its SectionReader. Source reads remain outside retries.
type retryPushWriter struct {
	content.Writer
	pusher   remotes.Pusher
	ctx      context.Context
	desc     ocispec.Descriptor
	cancel   context.CancelFunc
	unlock   func()
	attempts int
	exists   bool
	closed   bool
}

func (writer *retryPushWriter) open() error {
	for {
		if err := writer.ctx.Err(); err != nil {
			return err
		}
		writer.attempts++
		ctx, cancel := context.WithCancel(writer.ctx)
		remoteWriter, err := writer.pusher.Push(ctx, writer.desc)
		if err == nil {
			writer.Writer, writer.cancel = remoteWriter, cancel
			return nil
		}
		cancel()
		if err := writer.waitRetry(err); err != nil {
			return err
		}
	}
}

func (writer *retryPushWriter) waitRetry(err error) error {
	if ctxErr := writer.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if writer.attempts >= pushRetries || !isTransientPushError(err) {
		return err
	}
	logrus.Warnf("push %s attempt %d/%d failed, retrying: %v", writer.desc.Digest, writer.attempts, pushRetries, err)
	timer := time.NewTimer(time.Duration(writer.attempts) * 500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-writer.ctx.Done():
		return writer.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (writer *retryPushWriter) reset(err error) error {
	if ctxErr := writer.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, content.ErrReset) {
		if writer.attempts >= pushRetries {
			return errors.New("push reset retry limit exceeded")
		}
		writer.attempts++
		return content.ErrReset
	}
	if !isTransientPushError(err) || writer.attempts >= pushRetries {
		return err
	}
	if closeErr := writer.release(); closeErr != nil {
		return errors.Wrap(closeErr, "close failed push writer")
	}
	if err := writer.waitRetry(err); err != nil {
		return err
	}
	if err := writer.open(); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return err
		}
		writer.exists = true
	}
	return content.ErrReset
}

func (writer *retryPushWriter) Write(data []byte) (int, error) {
	if writer.closed {
		return 0, io.ErrClosedPipe
	}
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	if writer.exists {
		return len(data), nil
	}
	written, err := writer.Writer.Write(data)
	if err != nil {
		return written, writer.reset(err)
	}
	return written, nil
}

func (writer *retryPushWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	if writer.closed {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writer.ctx.Err(); err != nil {
		return err
	}
	if writer.exists {
		return nil
	}
	if err := writer.Writer.Commit(ctx, size, expected, opts...); err != nil {
		return writer.reset(err)
	}
	return nil
}

func (writer *retryPushWriter) Status() (content.Status, error) {
	if writer.closed {
		return content.Status{}, io.ErrClosedPipe
	}
	if err := writer.ctx.Err(); err != nil {
		return content.Status{}, err
	}
	if writer.exists {
		return content.Status{Offset: writer.desc.Size, Total: writer.desc.Size}, nil
	}
	return writer.Writer.Status()
}

func (writer *retryPushWriter) release() error {
	if writer.cancel == nil {
		return nil
	}
	writer.cancel()
	writer.cancel = nil
	return writer.Writer.Close()
}

func (writer *retryPushWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	defer writer.unlock()
	return writer.release()
}

func isTransientPushError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errdefs.IsAlreadyExists(err) {
		return false
	}
	var status remoteserrors.ErrUnexpectedStatus
	if errors.As(err, &status) {
		switch status.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		case http.StatusNotFound:
			requestURL, parseErr := url.Parse(status.RequestURL)
			if parseErr != nil || status.RequestMethod != http.MethodPut || !strings.Contains(requestURL.Path, "/blobs/uploads/") {
				return false
			}
			var response struct {
				Errors []struct{ Code string } `json:"errors"`
			}
			if json.Unmarshal(status.Body, &response) != nil {
				return false
			}
			for _, registryErr := range response.Errors {
				if registryErr.Code == "BLOB_UPLOAD_INVALID" || registryErr.Code == "BLOB_UPLOAD_UNKNOWN" {
					return true
				}
			}
		}
		return false
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsTemporary {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE)
}
