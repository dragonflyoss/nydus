// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"io"
	"sync"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/remotes"
	"github.com/docker/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Remote provides the ability to access remote registry
type Remote struct {
	// `Ref` is pointing to a remote image in formatted string host[:port]/[namespace/]repo[:tag]
	Ref    string
	parsed reference.Named
	// The resolver is used for image pull or fetches requests. The best practice
	// in containerd is that each resolver instance is used only once for a request
	// and is destroyed when the request completes. When a registry token expires,
	// the resolver does not re-apply for a new token, so it's better to create a
	// new resolver instance using resolverFunc for each request.
	resolverFunc func() remotes.Resolver
	pushed       sync.Map
}

// New creates remote instance from docker remote resolver
func New(ref string, resolverFunc func() remotes.Resolver) (*Remote, error) {
	parsed, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, err
	}

	return &Remote{
		Ref:          ref,
		parsed:       parsed,
		resolverFunc: resolverFunc,
	}, nil
}

// Push pushes blob to registry
func (remote *Remote) Push(ctx context.Context, desc ocispec.Descriptor, byDigest bool, reader io.Reader) error {
	// Concurrently push blob with same digest using containerd
	// docker remote client will cause error:
	// `failed commit on ref: unexpected size x, expected y`
	// use ref key leveled mutex lock to avoid the issue.
	refKey := remotes.MakeRefKey(ctx, desc)
	lock, _ := remote.pushed.LoadOrStore(refKey, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	pusher, err := remote.resolverFunc().Pusher(ctx, ref)
	if err != nil {
		return err
	}

	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer writer.Close()

	return content.Copy(ctx, writer, reader, desc.Size, desc.Digest)
}

// Pull pulls blob from registry
func (remote *Remote) Pull(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadCloser, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	puller, err := remote.resolverFunc().Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}

	reader, err := puller.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	return reader, nil
}

// Resolve parses descriptor for given image reference
func (remote *Remote) Resolve(ctx context.Context) (*ocispec.Descriptor, error) {
	ref := reference.TagNameOnly(remote.parsed).String()

	// Create a new resolver instance for the request
	_, desc, err := remote.resolverFunc().Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	return &desc, nil
}
