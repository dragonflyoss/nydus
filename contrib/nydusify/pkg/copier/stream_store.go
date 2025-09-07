// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// StreamStore wraps a content.Store and provides stream-based transfer capabilities
type StreamStore interface {
	content.Store
	// StreamTransfer performs stream-based transfer of content from source to target
	StreamTransfer(ctx context.Context, desc ocispec.Descriptor, sourceFetcher remotes.Fetcher, targetPusher remotes.Pusher, opt Opt) error
	// ReaderAt with stream capability awareness
	ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error)
}

// streamStore implements StreamStore interface
type streamStore struct {
	content.Store
	remotes []ocispec.Descriptor
}

// NewStreamStore creates a new StreamStore instance
func NewStreamStore(base content.Store, remotes []ocispec.Descriptor) StreamStore {
	return &streamStore{
		Store:   base,
		remotes: remotes,
	}
}

func (s *streamStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	info, err := s.Store.Info(ctx, dgst)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return content.Info{}, err
		}
		for _, desc := range s.remotes {
			if desc.Digest == dgst {
				return content.Info{
					Digest: desc.Digest,
					Size:   desc.Size,
				}, nil
			}
		}
		return content.Info{}, err
	}
	return info, nil
}

func (s *streamStore) StreamTransfer(ctx context.Context, desc ocispec.Descriptor, sourceFetcher remotes.Fetcher, targetPusher remotes.Pusher, opt Opt) error {
	// Check if content already exists in local store
	if _, err := s.Store.Info(ctx, desc.Digest); err == nil {
		// Content exists locally, use regular transfer
		return s.regularTransfer(ctx, desc, targetPusher, opt)
	}

	// Content not available locally, use stream transfer
	return s.streamTransfer(ctx, desc, sourceFetcher, targetPusher, opt)
}

func (s *streamStore) regularTransfer(ctx context.Context, desc ocispec.Descriptor, targetPusher remotes.Pusher, opt Opt) error {
	reader, err := s.Store.ReaderAt(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "open local content reader")
	}
	defer reader.Close()

	writer, err := targetPusher.Push(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "create target writer")
	}

	if writer == nil {
		return nil // Already exists
	}

	if err := StreamCopy(ctx, content.NewReader(reader), writer, desc.Size, desc.Digest, opt.PushChunkSize); err != nil {
		return errors.Wrap(err, "regular transfer failed")
	}

	return nil
}

func (s *streamStore) streamTransfer(ctx context.Context, desc ocispec.Descriptor, sourceFetcher remotes.Fetcher, targetPusher remotes.Pusher, opt Opt) error {
	logrus.Infof("start stream transfer: %s, size: %d", desc.Digest, desc.Size)

	rc, err := sourceFetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "fetch from source")
	}
	defer rc.Close()

	writer, err := targetPusher.Push(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "create target writer")
	}

	if writer == nil {
		return nil // Already exists
	}

	if err := StreamCopy(ctx, rc, writer, desc.Size, desc.Digest, opt.PushChunkSize); err != nil {
		return errors.Wrap(err, "stream transfer failed")
	}

	return nil
}

func (s *streamStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	// For stream contexts, we might want to handle this differently
	// but for now, delegate to the underlying store
	return s.Store.ReaderAt(ctx, desc)
}

// IsStreamContext checks if the context indicates stream transfer should be used
func IsStreamContext(ctx context.Context) bool {
	if val := ctx.Value(streamContextKey); val != nil {
		if useStream, ok := val.(bool); ok {
			return useStream
		}
	}
	return false
}
