/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package preheat

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	nydussnapshotterv1 "d7y.io/api/v2/pkg/apis/nydussnapshotter/v1"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	fsmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/preheat/mocks"
)

var (
	mockChainID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	mockImageRef = "registry.example.com/team/app:v1"

	mockNamespace = "default"

	mockImage = &fs.Image{ChainID: mockChainID, Ref: mockImageRef, BootstrapDir: "/var/lib/nydus-snapshotter/snapshots/2/fs"}

	mockCreatedAt = time.Unix(1700000000, 0).UTC()

	mockPreheat = &fs.Preheat{
		State: fs.PreheatStateRunning,
		Blobs: []fs.PreheatBlob{
			{Digest: "sha256:" + strings.Repeat("aa", 32), ContentLength: 512, FinishedContentLength: 512, IsFinished: true},
			{Digest: "sha256:" + strings.Repeat("bb", 32), ContentLength: 512},
		},
		CreatedAt: mockCreatedAt,
		UpdatedAt: mockCreatedAt.Add(time.Minute),
	}

	mockBasicRequest = &nydussnapshotterv1.PreheatImageRequest{
		Image: mockImageRef,
		Auth: &nydussnapshotterv1.PreheatImageRequest_BasicAuth{
			BasicAuth: &nydussnapshotterv1.BasicAuth{Username: "user", Password: "pass"},
		},
	}

	mockStatRequest = &nydussnapshotterv1.StatImageRequest{Image: mockImageRef}
)

func TestService_PreheatImage(t *testing.T) {
	tests := []struct {
		name   string
		req    *nydussnapshotterv1.PreheatImageRequest
		mock   func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, err error)
	}{
		{
			name: "queue a preheat read with a basic credential",
			req:  mockBasicRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.Preheat(gomock.Any(), mockImage, &fs.PreheatCredential{Username: "user", Password: "pass"}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "queue a preheat read with a bearer token in a namespace",
			req: &nydussnapshotterv1.PreheatImageRequest{
				Image:     mockImageRef,
				Namespace: &mockNamespace,
				Auth:      &nydussnapshotterv1.PreheatImageRequest_BearerToken{BearerToken: "token"},
			},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), mockNamespace, mockImageRef).Return(mockImage, nil).Times(1)
				mf.Preheat(gomock.Any(), mockImage, &fs.PreheatCredential{BearerToken: "token"}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "request without a credential",
			req:  &nydussnapshotterv1.PreheatImageRequest{Image: mockImageRef},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.InvalidArgument, status.Code(err))
				assert.ErrorContains(err, "PreheatImageRequest.Auth: value is required")
			},
		},
		{
			name: "request without an image",
			req: &nydussnapshotterv1.PreheatImageRequest{
				Auth: &nydussnapshotterv1.PreheatImageRequest_BearerToken{BearerToken: "token"},
			},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.InvalidArgument, status.Code(err))
				assert.ErrorContains(err, "PreheatImageRequest.Image")
			},
		},
		{
			name: "basic credential without a password does not echo the username",
			req: &nydussnapshotterv1.PreheatImageRequest{
				Image: mockImageRef,
				Auth: &nydussnapshotterv1.PreheatImageRequest_BasicAuth{
					BasicAuth: &nydussnapshotterv1.BasicAuth{Username: "user"},
				},
			},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.InvalidArgument, status.Code(err))
				assert.ErrorContains(err, "BasicAuth.Password")
				assert.NotContains(err.Error(), "user")
			},
		},
		{
			name: "username that holds a colon does not echo the credential",
			req: &nydussnapshotterv1.PreheatImageRequest{
				Image: mockImageRef,
				Auth: &nydussnapshotterv1.PreheatImageRequest_BasicAuth{
					BasicAuth: &nydussnapshotterv1.BasicAuth{Username: "us:er", Password: "pass"},
				},
			},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.InvalidArgument, status.Code(err))
				assert.NotContains(err.Error(), "us:er")
				assert.NotContains(err.Error(), "pass")
			},
		},
		{
			name: "image containerd has not pulled",
			req:  mockBasicRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(nil, fmt.Errorf("get image: %w", errdefs.ErrNotFound)).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.NotFound, status.Code(err))
			},
		},
		{
			name: "image that is not a nydus image",
			req:  mockBasicRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(nil, fmt.Errorf("not a nydus image: %w", errdefs.ErrFailedPrecondition)).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.FailedPrecondition, status.Code(err))
			},
		},
		{
			name: "containerd that cannot be reached",
			req:  mockBasicRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(nil, fmt.Errorf("connect: %w", errdefs.ErrUnavailable)).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.Unavailable, status.Code(err))
			},
		},
		{
			name: "preheat that cannot be queued",
			req:  mockBasicRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.Preheat(gomock.Any(), mockImage, gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Equal(codes.Unknown, status.Code(err))
				assert.ErrorContains(err, "foo")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			resolver := mocks.NewMockResolver(ctl)
			fileSystem := fsmocks.NewMockFileSystem(ctl)
			tc.mock(resolver.EXPECT(), fileSystem.EXPECT())

			_, err := NewService(resolver, fileSystem).PreheatImage(t.Context(), tc.req)
			tc.expect(t, err)
		})
	}
}

func TestService_StatImage(t *testing.T) {
	tests := []struct {
		name   string
		req    *nydussnapshotterv1.StatImageRequest
		mock   func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error)
	}{
		{
			name: "running preheat",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.StatPreheat(mockChainID).Return(mockPreheat, nil).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(resp.Validate())
				assert.Equal(nydussnapshotterv1.ImageState_RUNNING, resp.GetState())
				assert.Len(resp.GetBlobs(), 2)
				assert.Equal("sha256:"+strings.Repeat("aa", 32), resp.GetBlobs()[0].GetDigest())
				assert.Equal(uint64(512), resp.GetBlobs()[0].GetContentLength())
				assert.Equal(uint64(512), resp.GetBlobs()[0].GetFinishedContentLength())
				assert.True(resp.GetBlobs()[0].GetIsFinished())
				assert.Equal("sha256:"+strings.Repeat("bb", 32), resp.GetBlobs()[1].GetDigest())
				assert.Zero(resp.GetBlobs()[1].GetFinishedContentLength())
				assert.False(resp.GetBlobs()[1].GetIsFinished())
				assert.Nil(resp.Description)
				assert.Equal(mockCreatedAt, resp.GetCreatedAt().AsTime())
				assert.Equal(mockCreatedAt.Add(time.Minute), resp.GetUpdatedAt().AsTime())
			},
		},
		{
			name: "pending preheat of an image in a namespace",
			req:  &nydussnapshotterv1.StatImageRequest{Image: mockImageRef, Namespace: &mockNamespace},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), mockNamespace, mockImageRef).Return(mockImage, nil).Times(1)
				mf.StatPreheat(mockChainID).Return(&fs.Preheat{State: fs.PreheatStatePending, CreatedAt: mockCreatedAt, UpdatedAt: mockCreatedAt}, nil).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(nydussnapshotterv1.ImageState_PENDING, resp.GetState())
				assert.Empty(resp.GetBlobs())
			},
		},
		{
			name: "succeeded preheat",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				succeeded := *mockPreheat
				succeeded.State = fs.PreheatStateSucceeded
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.StatPreheat(mockChainID).Return(&succeeded, nil).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(nydussnapshotterv1.ImageState_SUCCEEDED, resp.GetState())
				assert.Len(resp.GetBlobs(), 2)
				assert.Nil(resp.Description)
			},
		},
		{
			name: "failed preheat",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				failed := *mockPreheat
				failed.State, failed.Description = fs.PreheatStateFailed, "blob sha256:aa: unexpected status 401 Unauthorized"
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.StatPreheat(mockChainID).Return(&failed, nil).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(nydussnapshotterv1.ImageState_FAILED, resp.GetState())
				assert.Equal("blob sha256:aa: unexpected status 401 Unauthorized", resp.GetDescription())
			},
		},
		{
			name: "request without an image",
			req:  &nydussnapshotterv1.StatImageRequest{},
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.Equal(codes.InvalidArgument, status.Code(err))
				assert.ErrorContains(err, "StatImageRequest.Image")
			},
		},
		{
			name: "image containerd has not pulled",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(nil, fmt.Errorf("get image: %w", errdefs.ErrNotFound)).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.Equal(codes.NotFound, status.Code(err))
			},
		},
		{
			name: "image that was not preheated",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(mockImage, nil).Times(1)
				mf.StatPreheat(mockChainID).Return(nil, fmt.Errorf("preheat: %w", errdefs.ErrNotFound)).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.Equal(codes.NotFound, status.Code(err))
			},
		},
		{
			name: "containerd that cannot be reached",
			req:  mockStatRequest,
			mock: func(mr *mocks.MockResolverMockRecorder, mf *fsmocks.MockFileSystemMockRecorder) {
				mr.Resolve(gomock.Any(), "k8s.io", mockImageRef).Return(nil, fmt.Errorf("connect: %w", errdefs.ErrUnavailable)).Times(1)
			},
			expect: func(t *testing.T, resp *nydussnapshotterv1.StatImageResponse, err error) {
				assert := assert.New(t)
				assert.Equal(codes.Unavailable, status.Code(err))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			resolver := mocks.NewMockResolver(ctl)
			fileSystem := fsmocks.NewMockFileSystem(ctl)
			tc.mock(resolver.EXPECT(), fileSystem.EXPECT())

			resp, err := NewService(resolver, fileSystem).StatImage(t.Context(), tc.req)
			tc.expect(t, resp, err)
		})
	}
}
