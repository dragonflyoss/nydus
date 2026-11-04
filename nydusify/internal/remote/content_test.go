/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	remoteserrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

var (
	errMock = errors.New("mock error")

	mockNetErr = &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}

	mockRef = "example.test/image:tag"

	mockLayer = []byte("layer")

	mockLayerDesc = mockDescriptor(ocispec.MediaTypeImageLayer, mockLayer)

	mockLargeLayer = bytes.Repeat(mockLayer, 20000)

	mockLargeLayerDesc = mockDescriptor(ocispec.MediaTypeImageLayer, mockLargeLayer)

	mockIndex = []byte(`{"schemaVersion":2,"manifests":[]}`)

	mockIndexDesc = mockDescriptor(ocispec.MediaTypeImageIndex, mockIndex)

	mockParentBlob = []byte("parent blob")

	mockParentBlobDesc = mockDescriptor(ocispec.MediaTypeImageLayer, mockParentBlob)
)

func mockDescriptor(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		resolver mockResolver
		expect   func(t *testing.T, err error)
	}{
		{
			name:     "resolve failure",
			ref:      mockRef,
			resolver: mockResolver{desc: mockLayerDesc, resolveErr: errMock},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
			},
		},
		{
			name:     "fetcher unavailable",
			ref:      mockRef,
			resolver: mockResolver{desc: mockLayerDesc, fetcherErr: errMock},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
			},
		},
		{
			name: "reject docker schema1 manifest",
			ref:  mockRef,
			resolver: mockResolver{desc: ocispec.Descriptor{
				MediaType: images.MediaTypeDockerSchema1Manifest,
				Digest:    mockLayerDesc.Digest,
				Size:      mockLayerDesc.Size,
			}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
			},
		},
		{
			name:     "invalid reference",
			ref:      "://invalid",
			resolver: mockResolver{desc: mockLayerDesc},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "build distribution source label handler")
			},
		},
		{
			name:     "fetch failure",
			ref:      mockRef,
			resolver: mockResolver{desc: mockLayerDesc, fetcher: &mockFetcher{err: errdefs.ErrNotFound}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			_, err = fetch(context.Background(), store, tc.resolver, tc.ref, platforms.All, PullAll)

			tc.expect(t, err)
		})
	}
}

func TestPush(t *testing.T) {
	tests := []struct {
		name      string
		desc      ocispec.Descriptor
		ref       string
		pusherErr error
		wrapper   func(images.Handler) images.Handler
		mock      func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher)
		expect    func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error)
	}{
		{
			name: "retry deferred index",
			desc: mockIndexDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.contents = map[digest.Digest][]byte{mockIndexDesc.Digest: mockIndex}
				pusher.commitErr = syscall.ECONNRESET
				pusher.failDigest = mockIndexDesc.Digest
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				var attempts []string
				for _, writer := range pusher.writers {
					if writer.desc.Digest == mockIndexDesc.Digest {
						attempts = append(attempts, writer.String())
					}
				}

				assert.Equal([]string{string(mockIndex), string(mockIndex)}, attempts)
			},
		},
		{
			name: "retry deferred manifest",
			desc: mockManifestDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.contents = mockImageBlobs
				pusher.commitErr = syscall.ECONNRESET
				pusher.failDigest = mockManifestDesc.Digest
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				var attempts []string
				for _, writer := range pusher.writers {
					if writer.desc.Digest == mockManifestDesc.Digest {
						attempts = append(attempts, writer.String())
					}
				}

				assert.Equal([]string{string(mockManifest), string(mockManifest)}, attempts)
			},
		},
		{
			name: "source open failure without backoff",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.openErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, store.opens)
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
				assert.Zero(elapsed)
			},
		},
		{
			name: "skip descriptors filtered by the handler wrapper",
			desc: mockManifestDesc,
			ref:  mockRef,
			wrapper: func(h images.Handler) images.Handler {
				return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
					if desc.Digest == mockNydusBlobDesc.Digest {
						return nil, images.ErrSkipDesc
					}

					return h.Handle(ctx, desc)
				})
			},
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.contents = mockImageBlobs
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(4, pusher.calls)
				for _, writer := range pusher.writers {
					assert.NotEqual(mockNydusBlobDesc.Digest, writer.desc.Digest)
				}
			},
		},
		{
			name: "retry remote open failure",
			desc: mockLargeLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.data = mockLargeLayer
				pusher.pushErr = mockNetErr
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(2, pusher.calls)
				assert.Equal(1, store.opens)
				assert.Equal([]mockUpload{{data: string(mockLargeLayer), commits: 1, closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "retry remote write failure",
			desc: mockLargeLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.data = mockLargeLayer
				pusher.writeErr = mockNetErr
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(2, pusher.calls)
				assert.Equal(1, store.opens)
				assert.Equal([]mockUpload{
					{data: string(mockLargeLayer[:len(mockLargeLayer)/2]), closes: 1},
					{data: string(mockLargeLayer), commits: 1, closes: 1},
				}, pusher.uploads())
				for _, reader := range store.readers {
					assert.Equal([]int64{0, 0}, reader.offsets)
				}
			},
		},
		{
			name: "retry remote commit failure",
			desc: mockLargeLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.data = mockLargeLayer
				pusher.commitErr = mockNetErr
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(2, pusher.calls)
				assert.Equal(1, store.opens)
				assert.Equal([]mockUpload{
					{data: string(mockLargeLayer), commits: 1, closes: 1},
					{data: string(mockLargeLayer), commits: 1, closes: 1},
				}, pusher.uploads())
				for _, reader := range store.readers {
					assert.Equal([]int64{0, 0}, reader.offsets)
				}
			},
		},
		{
			name: "stop retrying remote open failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.pushErr = remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusServiceUnavailable}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				var status remoteserrors.ErrUnexpectedStatus
				assert.ErrorAs(err, &status)
				assert.Equal(http.StatusServiceUnavailable, status.StatusCode)
				assert.Equal(pushRetries, pusher.calls)
			},
		},
		{
			name: "stop retrying remote write failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.writeErr = remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusServiceUnavailable}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				var status remoteserrors.ErrUnexpectedStatus
				assert.ErrorAs(err, &status)
				assert.Equal(http.StatusServiceUnavailable, status.StatusCode)
				assert.Equal(pushRetries, pusher.calls)
			},
		},
		{
			name: "stop retrying remote commit failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.commitErr = remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusServiceUnavailable}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				var status remoteserrors.ErrUnexpectedStatus
				assert.ErrorAs(err, &status)
				assert.Equal(http.StatusServiceUnavailable, status.StatusCode)
				assert.Equal(pushRetries, pusher.calls)
			},
		},
		{
			name: "stop resetting at the retry limit",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.commitErr = content.ErrReset
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push reset retry limit exceeded")
				assert.NotErrorIs(err, content.ErrReset)
				assert.Equal(1, pusher.calls)
				assert.Equal([]mockUpload{{commits: pushRetries, closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "permanent open failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.pushErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "permanent write failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.writeErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "permanent commit failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				pusher.commitErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "permanent source open failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				store.openErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "permanent source read failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.alwaysFail = true
				store.readErr = errMock
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "network source open failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.openErr = mockNetErr
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockNetErr)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "network source read failure",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				store.readErr = mockNetErr
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, mockNetErr)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "cancel before open",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				cancel()
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Zero(pusher.calls)
			},
		},
		{
			name: "cancel during open",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.onPush = func(context.Context) error {
					cancel()
					return syscall.ECONNRESET
				}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "cancel during write",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.onWrite = func(context.Context) error {
					cancel()
					return syscall.ECONNRESET
				}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "cancel during commit",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.onCommit = func(context.Context) error {
					cancel()
					return syscall.ECONNRESET
				}
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "cancel during backoff",
			desc: mockLayerDesc,
			ref:  mockRef,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {
				pusher.commitErr = syscall.ECONNRESET
				time.AfterFunc(time.Millisecond, cancel)
			},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name: "empty reference",
			desc: mockLayerDesc,
			mock: func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "empty push reference")
			},
		},
		{
			name:      "pusher unavailable",
			desc:      mockLayerDesc,
			ref:       mockRef,
			pusherErr: errMock,
			mock:      func(cancel context.CancelFunc, store *mockContentStore, pusher *mockPusher) {},
			expect: func(t *testing.T, store *mockContentStore, pusher *mockPusher, elapsed time.Duration, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				store := &mockContentStore{data: mockLayer}
				pusher := &mockPusher{}
				tc.mock(cancel, store, pusher)

				start := time.Now()
				err := push(ctx, store, mockResolver{pusher: pusher, pusherErr: tc.pusherErr}, tc.desc, tc.ref, platforms.All, tc.wrapper)

				tc.expect(t, store, pusher, time.Since(start), err)
				assert.Zero(t, pusher.ingesterCalls)
				for _, writer := range pusher.writers {
					assert.Equal(t, 1, writer.closes)
				}

				for _, pushCtx := range pusher.contexts {
					assert.ErrorIs(t, pushCtx.Err(), context.Canceled)
				}

				for _, reader := range store.readers {
					assert.Equal(t, 1, reader.closes)
				}
			})
		})
	}
}

func TestEnsureParentBlob(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		target   string
		pushErr  error
		writeErr error
		openErr  error
		resolver func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver
		expect   func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error)
	}{
		{
			name:    "mount without download",
			parent:  "registry.test:5000/ns/parent:v1",
			target:  "registry.test:5000/ns/child:v2",
			pushErr: errdefs.ErrAlreadyExists,
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{{
					MediaType:   mockParentBlobDesc.MediaType,
					Digest:      mockParentBlobDesc.Digest,
					Size:        mockParentBlobDesc.Size,
					Annotations: map[string]string{"containerd.io/distribution.source.registry.test": "ns/parent"},
				}}, pusher.descs)
				assert.Nil(mockParentBlobDesc.Annotations)
				assert.Empty(pusher.uploads())
			},
		},
		{
			name:   "fall back to upload",
			parent: "registry.test/ns/parent:v1",
			target: "registry.test/ns/child:v2",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcher: fetcher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(1, fetcher.calls)
				assert.Equal([]mockUpload{{data: string(mockParentBlob), commits: 1, closes: 1}}, pusher.uploads())
			},
		},
		{
			name:   "same repository",
			parent: "registry.test/ns/image:v1",
			target: "registry.test/ns/image:v2",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:   "different registries",
			parent: "source.test/ns/parent:v1",
			target: "target.test/ns/child:v2",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "same registry")
			},
		},
		{
			name:   "invalid parent reference",
			parent: "Parent/Image:v1",
			target: "registry.test/ns/child:v1",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse parent image "Parent/Image:v1"`)
				assert.Zero(pusher.calls)
			},
		},
		{
			name:   "invalid target reference",
			parent: "registry.test/ns/parent:v1",
			target: "Child/Image:v1",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse target image "Child/Image:v1"`)
				assert.Zero(pusher.calls)
			},
		},
		{
			name:   "pusher unavailable",
			parent: "registry.test/ns/parent:v1",
			target: "registry.test/ns/child:v1",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusherErr: errMock}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.ErrorContains(err, "create pusher for")
			},
		},
		{
			name:    "mount request fails",
			parent:  "registry.test/ns/parent:v1",
			target:  "registry.test/ns/child:v1",
			pushErr: errMock,
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.ErrorContains(err, "mount parent blob "+mockParentBlobDesc.Digest.String())
				assert.Equal(1, pusher.calls)
			},
		},
		{
			name:   "parent fetcher unavailable",
			parent: "registry.test/ns/parent:v1",
			target: "registry.test/ns/child:v1",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcherErr: errMock}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.ErrorContains(err, "get fetcher for parent")
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
			},
		},
		{
			name:   "parent download fails",
			parent: "registry.test/ns/parent:v1",
			target: "registry.test/ns/child:v1",
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcher: &mockFetcher{err: errdefs.ErrNotFound}}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.ErrorContains(err, "download parent blob")
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
			},
		},
		{
			name:    "downloaded parent cannot be opened",
			parent:  "registry.test/ns/parent:v1",
			target:  "registry.test/ns/child:v1",
			openErr: errMock,
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcher: fetcher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.ErrorContains(err, "open downloaded parent blob")
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
			},
		},
		{
			name:     "upload fails",
			parent:   "registry.test/ns/parent:v1",
			target:   "registry.test/ns/child:v1",
			writeErr: errMock,
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcher: fetcher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.ErrorContains(err, "upload parent blob")
				assert.Equal([]mockUpload{{data: string(mockParentBlob[:len(mockParentBlob)/2]), closes: 1}}, pusher.uploads())
			},
		},
		{
			name:     "blob published during upload",
			parent:   "registry.test/ns/parent:v1",
			target:   "registry.test/ns/child:v1",
			writeErr: errdefs.ErrAlreadyExists,
			resolver: func(pusher *mockPusher, fetcher *mockFetcher) remotes.Resolver {
				return mockResolver{pusher: pusher, fetcher: fetcher}
			},
			expect: func(t *testing.T, pusher *mockPusher, fetcher *mockFetcher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]mockUpload{{data: string(mockParentBlob[:len(mockParentBlob)/2]), closes: 1}}, pusher.uploads())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, err := local.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			pusher := &mockPusher{pushErr: tc.pushErr, writeErr: tc.writeErr}
			fetcher := &mockFetcher{Reader: bytes.NewReader(mockParentBlob)}
			store := &mockContentStore{Store: base, data: mockParentBlob, openErr: tc.openErr}
			err = ensureParentBlob(context.Background(), store, tc.resolver(pusher, fetcher), mockParentBlobDesc, tc.parent, tc.target)

			tc.expect(t, pusher, fetcher, err)
		})
	}
}

func TestPushBlobFile(t *testing.T) {
	tests := []struct {
		name      string
		pusherErr error
		mock      func(t *testing.T, path string, pusher *mockPusher)
		expect    func(t *testing.T, pusher *mockPusher, err error)
	}{
		{
			name: "upload blob file",
			mock: func(t *testing.T, path string, pusher *mockPusher) {},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]mockUpload{{data: string(mockBlobFile), commits: 1, closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "skip existing remote blob",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				pusher.pushErr = errdefs.ErrAlreadyExists
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(pusher.uploads())
			},
		},
		{
			name: "missing blob file",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat blob file")
				assert.Empty(pusher.uploads())
			},
		},
		{
			name: "blob file size changed",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "size changed")
				assert.Empty(pusher.uploads())
			},
		},
		{
			name:      "pusher unavailable",
			pusherErr: errMock,
			mock:      func(t *testing.T, path string, pusher *mockPusher) {},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Empty(pusher.uploads())
			},
		},
		{
			name: "writer unavailable",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				pusher.pushErr = errMock
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Empty(pusher.uploads())
			},
		},
		{
			name: "blob file removed before open",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				pusher.onPush = func(context.Context) error {
					return os.Remove(path)
				}
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob file")
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "upload failure",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				pusher.writeErr = errMock
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMock)
				assert.Equal([]mockUpload{{data: string(mockBlobFile[:len(mockBlobFile)/2]), closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "blob published during upload",
			mock: func(t *testing.T, path string, pusher *mockPusher) {
				pusher.writeErr = errdefs.ErrAlreadyExists
			},
			expect: func(t *testing.T, pusher *mockPusher, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]mockUpload{{data: string(mockBlobFile[:len(mockBlobFile)/2]), closes: 1}}, pusher.uploads())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blob")
			if err := os.WriteFile(path, mockBlobFile, 0o600); err != nil {
				t.Fatal(err)
			}

			pusher := &mockPusher{}
			tc.mock(t, path, pusher)
			err := pushBlobFile(context.Background(), mockResolver{pusher: pusher, pusherErr: tc.pusherErr}, mockBlobFileDesc, mockRef, path)

			tc.expect(t, pusher, err)
		})
	}
}

func TestRetryPusher_Push(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, retrying *retryPusher, pusher *mockPusher)
	}{
		{
			name: "serialize writers for the same descriptor",
			expect: func(t *testing.T, retrying *retryPusher, pusher *mockPusher) {
				assert := assert.New(t)
				first, err := retrying.Push(context.Background(), mockLayerDesc)
				assert.NoError(err)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() {
					_, err := retrying.Push(ctx, mockLayerDesc)
					done <- err
				}()

				synctest.Wait()
				assert.Equal(1, pusher.calls)
				cancel()
				assert.ErrorIs(<-done, context.Canceled)
				assert.NoError(first.Close())
				assert.NoError(first.Close())
				second, err := retrying.Push(context.Background(), mockLayerDesc)
				assert.NoError(err)
				assert.NoError(second.Close())
				assert.Equal(2, pusher.calls)
				assert.Zero(pusher.ingesterCalls)
				assert.Equal([]mockUpload{{closes: 1}, {closes: 1}}, pusher.uploads())
				for _, pushCtx := range pusher.contexts {
					assert.ErrorIs(pushCtx.Err(), context.Canceled)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pusher := &mockPusher{}

				tc.expect(t, &retryPusher{pusher: pusher}, pusher)
			})
		})
	}
}

func TestRetryPushWriter_Write(t *testing.T) {
	tests := []struct {
		name      string
		reopenErr error
		expect    func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher)
	}{
		{
			name:      "return reopen failure",
			reopenErr: errdefs.ErrPermissionDenied,
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher) {
				assert := assert.New(t)
				_, err := w.Write(mockLayer)
				assert.ErrorIs(err, errdefs.ErrPermissionDenied)
				assert.NotErrorIs(err, content.ErrReset)
				assert.Equal(2, pusher.calls)
				assert.Equal([]mockUpload{{data: string(mockLayer[:len(mockLayer)/2]), closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "reset upload after transient failure",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher) {
				assert := assert.New(t)
				_, err := w.Write(mockLayer)
				assert.ErrorIs(err, content.ErrReset)
				assert.Equal(2, pusher.calls)
				assert.Equal([]mockUpload{{data: string(mockLayer[:len(mockLayer)/2]), closes: 1}, {}}, pusher.uploads())
			},
		},
		{
			name:      "skip upload published during retry",
			reopenErr: errdefs.ErrAlreadyExists,
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher) {
				assert := assert.New(t)
				_, err := w.Write(mockLayer)
				assert.ErrorIs(err, content.ErrReset)
				status, err := w.Status()
				assert.NoError(err)
				assert.Equal(mockLayerDesc.Size, status.Offset)
				n, err := w.Write(mockLayer)
				assert.NoError(err)
				assert.Equal(len(mockLayer), n)
				assert.NoError(w.Commit(context.Background(), mockLayerDesc.Size, mockLayerDesc.Digest))
				assert.Equal([]mockUpload{{data: string(mockLayer[:len(mockLayer)/2]), closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "write to closed writer",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher) {
				assert := assert.New(t)
				assert.NoError(w.Close())
				_, err := w.Write(mockLayer)
				assert.ErrorIs(err, io.ErrClosedPipe)
				assert.Equal([]mockUpload{{closes: 1}}, pusher.uploads())
			},
		},
		{
			name: "write with canceled context",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer, pusher *mockPusher) {
				assert := assert.New(t)
				cancel()
				_, err := w.Write(mockLayer)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal([]mockUpload{{}}, pusher.uploads())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				pusher := &mockPusher{writeErr: syscall.ECONNRESET}
				pusher.onPush = func(context.Context) error {
					if pusher.calls == 2 {
						return tc.reopenErr
					}

					return nil
				}

				w, err := (&retryPusher{pusher: pusher}).Push(ctx, mockLayerDesc)
				if err != nil {
					t.Fatal(err)
				}

				tc.expect(t, cancel, w, pusher)
				assert.NoError(t, w.Close())
			})
		})
	}
}

func TestRetryPushWriter_Commit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, cancel context.CancelFunc, w content.Writer)
	}{
		{
			name: "commit closed writer",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer) {
				assert := assert.New(t)
				assert.NoError(w.Close())
				assert.ErrorIs(w.Commit(context.Background(), mockLayerDesc.Size, mockLayerDesc.Digest), io.ErrClosedPipe)
			},
		},
		{
			name: "commit with canceled writer context",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer) {
				assert := assert.New(t)
				cancel()
				assert.ErrorIs(w.Commit(context.Background(), mockLayerDesc.Size, mockLayerDesc.Digest), context.Canceled)
			},
		},
		{
			name: "commit with canceled commit context",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer) {
				assert := assert.New(t)
				ctx, stop := context.WithCancel(context.Background())
				stop()
				assert.ErrorIs(w.Commit(ctx, mockLayerDesc.Size, mockLayerDesc.Digest), context.Canceled)
				assert.NoError(w.Commit(context.Background(), mockLayerDesc.Size, mockLayerDesc.Digest))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w, err := (&retryPusher{pusher: &mockPusher{}}).Push(ctx, mockLayerDesc)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, cancel, w)
			assert.NoError(t, w.Close())
		})
	}
}

func TestRetryPushWriter_Status(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, cancel context.CancelFunc, w content.Writer)
	}{
		{
			name: "status of closed writer",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer) {
				assert := assert.New(t)
				assert.NoError(w.Close())
				_, err := w.Status()
				assert.ErrorIs(err, io.ErrClosedPipe)
			},
		},
		{
			name: "status with canceled context",
			expect: func(t *testing.T, cancel context.CancelFunc, w content.Writer) {
				assert := assert.New(t)
				cancel()
				_, err := w.Status()
				assert.ErrorIs(err, context.Canceled)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w, err := (&retryPusher{pusher: &mockPusher{}}).Push(ctx, mockLayerDesc)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, cancel, w)
			assert.NoError(t, w.Close())
		})
	}
}

func TestIsTransientPushError(t *testing.T) {
	mockUploadErr := func(code string) error {
		return remoteserrors.ErrUnexpectedStatus{
			StatusCode:    http.StatusNotFound,
			RequestMethod: http.MethodPut,
			RequestURL:    "https://example.test/v2/image/blobs/uploads/session",
			Body:          []byte(fmt.Sprintf(`{"errors":[{"code":%q}]}`, code)),
		}
	}

	tests := []struct {
		name   string
		err    error
		expect func(t *testing.T, transient bool)
	}{
		{
			name: "nil error",
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "canceled context",
			err:  context.Canceled,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "already exists",
			err:  errdefs.ErrAlreadyExists,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "unavailable",
			err:  errdefs.ErrUnavailable,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "invalid argument",
			err:  errdefs.ErrInvalidArgument,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "permission denied",
			err:  syscall.EACCES,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "unknown certificate authority",
			err:  x509.UnknownAuthorityError{},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "dns host not found",
			err:  &net.DNSError{IsNotFound: true},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "dns timeout",
			err:  &net.DNSError{IsTimeout: true},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "temporary dns failure",
			err:  &net.DNSError{IsTemporary: true},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "dial temporary dns failure",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{IsTemporary: true}},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "connection reset",
			err:  mockNetErr,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "broken pipe",
			err:  syscall.EPIPE,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "unexpected eof",
			err:  io.ErrUnexpectedEOF,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "eof",
			err:  io.EOF,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "closed pipe",
			err:  io.ErrClosedPipe,
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "invalid blob upload",
			err:  mockUploadErr("BLOB_UPLOAD_INVALID"),
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "unknown blob upload",
			err:  mockUploadErr("BLOB_UPLOAD_UNKNOWN"),
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "unknown blob",
			err:  mockUploadErr("BLOB_UNKNOWN"),
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "status only in message",
			err:  errors.New("503 Service Unavailable"),
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "bad request status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusBadRequest},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "unauthorized status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusUnauthorized},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "forbidden status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusForbidden},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "not found status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusNotFound},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "request timeout status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusRequestTimeout},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "too many requests status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusTooManyRequests},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "internal server error status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusInternalServerError},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "not implemented status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusNotImplemented},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.False(transient)
			},
		},
		{
			name: "bad gateway status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusBadGateway},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "service unavailable status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusServiceUnavailable},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
		{
			name: "gateway timeout status",
			err:  remoteserrors.ErrUnexpectedStatus{StatusCode: http.StatusGatewayTimeout},
			expect: func(t *testing.T, transient bool) {
				assert := assert.New(t)
				assert.True(transient)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transient := isTransientPushError(tc.err)
			assert.Equal(t, transient, isTransientPushError(fmt.Errorf("wrapped: %w", tc.err)))

			tc.expect(t, transient)
		})
	}
}

type mockResolver struct {
	desc       ocispec.Descriptor
	pusher     remotes.Pusher
	fetcher    remotes.Fetcher
	resolveErr error
	fetcherErr error
	pusherErr  error
}

func (r mockResolver) Resolve(_ context.Context, ref string) (string, ocispec.Descriptor, error) {
	return ref, r.desc, r.resolveErr
}

func (r mockResolver) Fetcher(context.Context, string) (remotes.Fetcher, error) {
	return r.fetcher, r.fetcherErr
}

func (r mockResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return r.pusher, r.pusherErr
}

type mockFetcher struct {
	io.Reader
	err    error
	calls  int
	closes int
}

func (f *mockFetcher) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	f.calls++
	return f, f.err
}

func (f *mockFetcher) Close() error {
	f.closes++
	return nil
}

type mockContentStore struct {
	content.Store
	mu       sync.Mutex
	data     []byte
	contents map[digest.Digest][]byte
	openErr  error
	readErr  error
	opens    int
	readers  []*mockReader
}

func (s *mockContentStore) ReaderAt(_ context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opens++
	if s.openErr != nil {
		return nil, s.openErr
	}

	data := s.data
	if s.contents != nil {
		data = s.contents[desc.Digest]
	}

	reader := &mockReader{Reader: bytes.NewReader(data), readErr: s.readErr}
	s.readers = append(s.readers, reader)
	return reader, nil
}

func (s *mockContentStore) Info(context.Context, digest.Digest) (content.Info, error) {
	return content.Info{}, errdefs.ErrNotFound
}

type mockReader struct {
	*bytes.Reader
	readErr error
	offsets []int64
	closes  int
}

func (r *mockReader) ReadAt(data []byte, offset int64) (int, error) {
	r.offsets = append(r.offsets, offset)
	read, err := r.Reader.ReadAt(data, offset)
	if r.readErr != nil {
		return read, r.readErr
	}

	return read, err
}

func (r *mockReader) Close() error {
	r.closes++
	return nil
}

type mockUpload struct {
	data    string
	commits int
	closes  int
}

type mockPusher struct {
	mu            sync.Mutex
	writers       []*mockWriter
	contexts      []context.Context
	descs         []ocispec.Descriptor
	calls         int
	ingesterCalls int
	failures      int
	active        bool
	alwaysFail    bool
	failDigest    digest.Digest
	pushErr       error
	writeErr      error
	commitErr     error
	onPush        func(context.Context) error
	onWrite       func(context.Context) error
	onCommit      func(context.Context) error
}

func (p *mockPusher) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	p.mu.Lock()
	p.ingesterCalls++
	if p.active {
		p.mu.Unlock()
		return nil, errdefs.ErrUnavailable
	}

	p.mu.Unlock()
	var options content.WriterOpts
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	return p.Push(ctx, options.Desc)
}

func (p *mockPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.contexts = append(p.contexts, ctx)
	p.descs = append(p.descs, desc)
	if p.onPush != nil {
		if err := p.onPush(ctx); err != nil {
			return nil, err
		}
	}

	writer := &mockWriter{pusher: p, desc: desc, ctx: ctx}
	if (p.failDigest == "" || p.failDigest == desc.Digest) && (p.alwaysFail || p.failures == 0) {
		p.failures++
		if p.pushErr != nil {
			return nil, p.pushErr
		}

		writer.writeErr, writer.commitErr = p.writeErr, p.commitErr
	}

	p.writers = append(p.writers, writer)
	p.active = true
	return writer, nil
}

func (p *mockPusher) uploads() []mockUpload {
	p.mu.Lock()
	defer p.mu.Unlock()
	uploads := make([]mockUpload, 0, len(p.writers))
	for _, writer := range p.writers {
		uploads = append(uploads, mockUpload{data: writer.String(), commits: writer.commits, closes: writer.closes})
	}

	return uploads
}

type mockWriter struct {
	bytes.Buffer
	pusher    *mockPusher
	desc      ocispec.Descriptor
	ctx       context.Context
	writeErr  error
	commitErr error
	closes    int
	commits   int
}

func (w *mockWriter) Write(data []byte) (int, error) {
	if w.pusher.onWrite != nil {
		if err := w.pusher.onWrite(w.ctx); err != nil {
			return 0, err
		}
	}

	if w.writeErr != nil {
		written, _ := w.Buffer.Write(data[:len(data)/2])
		return written, w.writeErr
	}

	return w.Buffer.Write(data)
}

func (w *mockWriter) Close() error {
	w.closes++
	w.pusher.mu.Lock()
	defer w.pusher.mu.Unlock()
	if w.Len() > 0 {
		w.pusher.active = false
	}

	return nil
}

func (w *mockWriter) Status() (content.Status, error) {
	return content.Status{Offset: int64(w.Len()), Total: w.desc.Size}, nil
}

func (w *mockWriter) Digest() digest.Digest {
	return w.desc.Digest
}

func (w *mockWriter) Commit(context.Context, int64, digest.Digest, ...content.Opt) error {
	w.commits++
	if w.pusher.onCommit != nil {
		if err := w.pusher.onCommit(w.ctx); err != nil {
			return err
		}
	}

	if errors.Is(w.commitErr, content.ErrReset) {
		w.Reset()
	}

	return w.commitErr
}

func (w *mockWriter) Truncate(size int64) error {
	w.Buffer.Truncate(int(size))
	return nil
}
