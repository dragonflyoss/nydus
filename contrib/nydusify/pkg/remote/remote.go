// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
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
	resolverFunc func(insecure bool) remotes.Resolver
	pushed       sync.Map

	withHTTP bool
}

// New creates remote instance from docker remote resolver
func New(ref string, resolverFunc func(bool) remotes.Resolver) (*Remote, error) {
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

func (remote *Remote) MaybeWithHTTP(err error) {
	parsed, _ := reference.ParseNormalizedNamed(remote.Ref)
	if parsed != nil {
		host := reference.Domain(parsed)
		// If the error message includes the current registry host string, it
		// implies that we can retry the request with plain HTTP.
		if strings.Contains(err.Error(), fmt.Sprintf("/%s/", host)) {
			remote.withHTTP = true
		}
	}
}

func (remote *Remote) WithHTTP() {
	remote.withHTTP = true
}
func (remote *Remote) IsWithHTTP() bool {
	return remote.withHTTP
}

func (remote *Remote) namedReference() (reference.Named, error) {
	if remote.parsed != nil {
		return remote.parsed, nil
	}
	if remote.Ref == "" {
		return nil, errors.New("empty remote reference")
	}
	parsed, err := reference.ParseNormalizedNamed(remote.Ref)
	if err != nil {
		return nil, err
	}
	remote.parsed = parsed
	return parsed, nil
}

func (remote *Remote) requestRef(byDigest bool) (string, error) {
	parsed, err := remote.namedReference()
	if err != nil {
		return "", err
	}
	if byDigest {
		return parsed.Name(), nil
	}
	return reference.TagNameOnly(parsed).String(), nil
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

	ref, err := remote.requestRef(byDigest)
	if err != nil {
		return err
	}

	// Create a new resolver instance for the request
	pusher, err := remote.resolverFunc(remote.withHTTP).Pusher(ctx, ref)
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
	ref, err := remote.requestRef(byDigest)
	if err != nil {
		return nil, err
	}

	// Create a new resolver instance for the request
	puller, err := remote.resolverFunc(remote.withHTTP).Fetcher(ctx, ref)
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
	ref, err := remote.requestRef(false)
	if err != nil {
		return nil, err
	}

	// Create a new resolver instance for the request
	_, desc, err := remote.resolverFunc(remote.withHTTP).Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	return &desc, nil
}
