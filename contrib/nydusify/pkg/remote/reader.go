// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"io"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// FromFetcher creates a content.Provider based on remotes.Fetcher
func FromFetcher(f remotes.Fetcher) content.Provider {
	return &fetchedProvider{
		f: f,
	}
}

type fetchedProvider struct {
	f remotes.Fetcher
}

func (p *fetchedProvider) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	rc, err := p.f.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	return &readerAt{Reader: rc, Closer: rc, size: desc.Size}, nil
}

// readerAt implements content.ReaderAt interface for reading content with random access
type readerAt struct {
	io.Reader
	io.Closer
	size   int64
	offset int64
}

// ReadAt implements io.ReaderAt interface for random access reading
// It handles seeking to the correct offset and reading the requested data
func (ra *readerAt) ReadAt(p []byte, off int64) (int, error) {
	if ra.offset != off {
		if seeker, ok := ra.Reader.(io.Seeker); ok {
			if _, err := seeker.Seek(off, io.SeekStart); err != nil {
				return 0, err
			}
			ra.offset = off
		} else {
			return 0, errors.New("reader does not support seeking")
		}
	}

	var totalN int
	for len(p) > 0 {
		n, err := ra.Reader.Read(p)
		if err == io.EOF && n == len(p) {
			err = nil
		}
		ra.offset += int64(n)
		totalN += n
		p = p[n:]
		if err != nil {
			return totalN, err
		}
	}
	return totalN, nil
}

// Size returns the total size of the content being read
func (ra *readerAt) Size() int64 {
	return ra.size
}

// ReaderAt returns a content.ReaderAt for reading remote blobs
// It creates a new resolver instance for each request to ensure thread safety
func (remote *Remote) ReaderAt(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (content.ReaderAt, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	fetcher, err := remote.resolverFunc(remote.withHTTP).Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}

	// Create Provider using FromFetcher
	provider := FromFetcher(fetcher)
	return provider.ReaderAt(ctx, desc)
}

func (remote *Remote) ReadSeekCloser(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadSeekCloser, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	// Create a new resolver instance for the request
	fetcher, err := remote.resolverFunc(remote.withHTTP).Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}

	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	rsc, ok := rc.(io.ReadSeekCloser)
	if !ok {
		return nil, errors.New("fetcher does not support ReadSeekCloser")
	}
	return rsc, nil
}
