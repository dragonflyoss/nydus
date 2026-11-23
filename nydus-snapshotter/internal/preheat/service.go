/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package preheat serves the NydusSnapshotter gRPC API, which downloads
// every blob of an image containerd has pulled to the node.
package preheat

import (
	"cmp"
	"context"
	"strings"

	nydussnapshotterv1 "d7y.io/api/v2/pkg/apis/nydussnapshotter/v1"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

const (
	// defaultNamespace is the containerd namespace of the images kubelet
	// pulls, refer to
	// https://github.com/containerd/containerd/blob/v2.2.10/internal/cri/constants/constants.go.
	defaultNamespace = "k8s.io"
)

// Service is the NydusSnapshotter gRPC service, served on the snapshotter's
// socket next to containerd's snapshots service, refer to the Preheat section
// of docs/snapshotter.md. Both calls name the image, as PreheatImage and
// StatImage of Dragonfly's scheduler do.
//
//	PreheatImage ─▶ resolve the image ─▶ queue ─▶ nydus preheat downloads
//	StatImage    ─▶ resolve the image ─▶ state of its preheat and of its blobs
type Service struct {
	// UnimplementedNydusSnapshotterServer answers an RPC a newer API adds
	// with Unimplemented.
	nydussnapshotterv1.UnimplementedNydusSnapshotterServer

	// resolver resolves the image a call names.
	resolver Resolver

	// fileSystem runs the preheats.
	fileSystem fs.FileSystem
}

// NewService returns the NydusSnapshotter gRPC service.
func NewService(resolver Resolver, fileSystem fs.FileSystem) *Service {
	return &Service{resolver: resolver, fileSystem: fileSystem}
}

// PreheatImage resolves an image containerd has pulled and queues its
// preheat. The credential of the request is used by this preheat only; no
// error names it.
func (s *Service) PreheatImage(ctx context.Context, req *nydussnapshotterv1.PreheatImageRequest) (*emptypb.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	credential := &fs.PreheatCredential{
		Username:    req.GetBasicAuth().GetUsername(),
		Password:    req.GetBasicAuth().GetPassword(),
		BearerToken: req.GetBearerToken(),
	}

	// A colon ends the username of a basic credential, refer to
	// https://datatracker.ietf.org/doc/html/rfc7617#section-2.
	if strings.Contains(credential.Username, ":") {
		return nil, status.Error(codes.InvalidArgument, "invalid PreheatImageRequest.BasicAuth.Username: value must not contain a colon")
	}

	image, err := s.resolver.Resolve(ctx, cmp.Or(req.GetNamespace(), defaultNamespace), req.GetImage())
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	if err := s.fileSystem.Preheat(ctx, image, credential); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

// StatImage resolves an image containerd has pulled and returns the state
// of its preheat and of every blob of the image.
func (s *Service) StatImage(ctx context.Context, req *nydussnapshotterv1.StatImageRequest) (*nydussnapshotterv1.StatImageResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	image, err := s.resolver.Resolve(ctx, cmp.Or(req.GetNamespace(), defaultNamespace), req.GetImage())
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	preheat, err := s.fileSystem.StatPreheat(image.ChainID)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	return s.statImageResponse(preheat), nil
}

// statImageResponse returns a preheat as the response of StatImage.
func (s *Service) statImageResponse(preheat *fs.Preheat) *nydussnapshotterv1.StatImageResponse {
	resp := &nydussnapshotterv1.StatImageResponse{
		State:     nydussnapshotterv1.ImageState_PENDING,
		CreatedAt: timestamppb.New(preheat.CreatedAt),
		UpdatedAt: timestamppb.New(preheat.UpdatedAt),
	}

	for _, blob := range preheat.Blobs {
		resp.Blobs = append(resp.Blobs, &nydussnapshotterv1.Blob{
			Digest:                blob.Digest,
			ContentLength:         blob.ContentLength,
			FinishedContentLength: blob.FinishedContentLength,
			IsFinished:            blob.IsFinished,
		})
	}

	switch preheat.State {
	case fs.PreheatStateRunning:
		resp.State = nydussnapshotterv1.ImageState_RUNNING
	case fs.PreheatStateSucceeded:
		resp.State = nydussnapshotterv1.ImageState_SUCCEEDED
	case fs.PreheatStateFailed:
		resp.State = nydussnapshotterv1.ImageState_FAILED
	}

	if preheat.Description != "" {
		resp.Description = &preheat.Description
	}

	return resp
}
