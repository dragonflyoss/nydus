/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference/docker"
	"github.com/golang/groupcache/lru"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/pkg/errors"
)

const (
	stargzFooterSize = 47
	stargzToc        = "stargz.index.json"
)

type Resolver struct {
	trPoolMu  sync.Mutex
	trPool    *lru.Cache
	transport http.RoundTripper
}

func NewResolver() *Resolver {
	resolver := Resolver{
		transport: http.DefaultTransport,
		trPool:    lru.New(3000),
	}
	return &resolver
}

type Blob struct {
	ref    string
	digest string
	sr     *io.SectionReader
}

// getTocOffset get toc offset from stargz footer
func (bb *Blob) getTocOffset() (int64, error) {
	b := make([]byte, stargzFooterSize)
	_, err := bb.sr.ReadAt(b[:], bb.sr.Size()-stargzFooterSize)
	if err != nil && err != io.EOF {
		return 0, err
	}
	if tocOffset, ok := parseFooter(b); ok {
		return tocOffset, nil
	}
	return 0, fmt.Errorf("failed to parse stargz footer of ref %s digest %s", bb.ref, bb.digest)
}

// ReadToc read stargz toc content from blob
func (bb *Blob) ReadToc() (io.Reader, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		log.L.Infof("read toc duration %d", duration.Milliseconds())
	}()

	tocOffset, err := bb.getTocOffset()
	if err != nil {
		return nil, err
	}
	tocBuf := make([]byte, bb.sr.Size()-tocOffset-stargzFooterSize)
	_, err = bb.sr.ReadAt(tocBuf, tocOffset)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(tocBuf))
	if err != nil {
		return nil, err
	}
	zr.Multistream(false)
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil {
		return nil, err
	}
	if h.Name != stargzToc {
		return nil, fmt.Errorf("failed to find toc from image %s blob %s", bb.ref, bb.digest)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(tr)
	if err != nil {
		return nil, err
	}
	return &buf, nil
}

func (r *Resolver) GetBlob(ref, digest string, keychain authn.Keychain) (*Blob, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		log.L.Infof("get blob duration %d", duration.Milliseconds())
	}()

	sr, err := r.resolve(ref, digest, keychain)
	if err != nil {
		return nil, err
	}
	return &Blob{
		ref:    ref,
		digest: digest,
		sr:     sr,
	}, nil
}

type readerAtFunc func([]byte, int64) (int, error)

func (f readerAtFunc) ReadAt(p []byte, offset int64) (int, error) { return f(p, offset) }

// parseFooter extract toc offset from footer
func parseFooter(p []byte) (tocOffset int64, ok bool) {
	if len(p) != 47 {
		return 0, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(p))
	if err != nil {
		return 0, false
	}
	extra := zr.Header.Extra
	if len(extra) != 16+len("STARGZ") {
		return 0, false
	}
	if string(extra[16:]) != "STARGZ" {
		return 0, false
	}
	tocOffset, err = strconv.ParseInt(string(extra[:16]), 16, 64)
	return tocOffset, err == nil
}

func (r *Resolver) resolve(ref, digest string, keychain authn.Keychain) (*io.SectionReader, error) {
	named, err := docker.ParseDockerRef(ref)
	if err != nil {
		return nil, err
	}
	host := docker.Domain(named)
	sref := fmt.Sprintf("%s/%s", host, docker.Path(named))
	nref, err := name.ParseReference(sref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse ref %q (%q)", sref, digest)
	}

	url, tr, err := r.resolveReference(nref, digest, keychain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve reference of %q, %q", nref, digest)
	}

	size, err := getSize(url, tr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get size from url %s", url)
	}
	log.L.Infof("get size %d", size)

	sr := io.NewSectionReader(readerAtFunc(func(b []byte, offset int64) (int, error) {
		length := len(b)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0, nil
		}
		req.Close = false
		r := fmt.Sprintf("bytes=%d-%d", offset, offset+int64(length)-1)
		req.Header.Set("Range", r)
		res, err := tr.RoundTrip(req)
		if err != nil {
			return 0, err
		}
		defer func() {
			io.Copy(ioutil.Discard, res.Body)
			res.Body.Close()
		}()
		if res.StatusCode/100 != 2 {
			return 0, fmt.Errorf("failed to HEAD request with code %d", res.StatusCode)
		}
		return io.ReadFull(res.Body, b)
	}), 0, size)

	return sr, nil
}

func (r *Resolver) resolveReference(ref name.Reference, digest string, keychain authn.Keychain) (string, http.RoundTripper, error) {
	r.trPoolMu.Lock()
	defer r.trPoolMu.Unlock()
	endpointURL := fmt.Sprintf("%s://%s/v2/%s/blobs/%s",
		ref.Context().Registry.Scheme(),
		ref.Context().RegistryStr(),
		ref.Context().RepositoryStr(),
		digest)

	if tr, ok := r.trPool.Get(ref.Name()); ok {
		if url, err := redirect(endpointURL, tr.(http.RoundTripper)); err != nil {
			return url, tr.(http.RoundTripper), nil
		}
	}
	r.trPool.Remove(ref.Name())
	tr, err := authnTransport(ref, r.transport, keychain)
	if err != nil {
		return "", nil, err
	}
	url, err := redirect(endpointURL, tr)
	if err != nil {
		return "", nil, err
	}
	r.trPool.Add(ref.Name(), tr)
	return url, tr, nil
}

func authnTransport(ref name.Reference, tr http.RoundTripper, keychain authn.Keychain) (http.RoundTripper, error) {
	if keychain == nil {
		return nil, fmt.Errorf("keychain is required")
	}
	auth, err := keychain.Resolve(ref.Context())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve reference %q", ref)
	}
	errCh := make(chan error)
	var rTr http.RoundTripper
	go func() {
		rTr, err = transport.New(
			ref.Context().Registry,
			auth,
			tr,
			[]string{ref.Scope(transport.PullScope)},
		)
		errCh <- err
	}()
	select {
	case err = <-errCh:
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("authentication timeout")
	}
	return rTr, err
}

func redirect(endpointURL string, tr http.RoundTripper) (url string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", endpointURL, nil)
	if err != nil {
		return "", errors.Wrapf(err, "failed to request to the registry")
	}
	req.Close = false
	req.Header.Set("Range", "bytes=0-0")
	res, err := tr.RoundTrip(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to request to %q", endpointURL)
	}
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode/100 == 2 {
		url = endpointURL
	} else if redir := res.Header.Get("Location"); redir != "" && res.StatusCode/100 == 3 {
		url = redir
	} else {
		return "", fmt.Errorf("failed to access to %q with code %v", endpointURL, res.StatusCode)
	}
	return
}

func getSize(url string, tr http.RoundTripper) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil
	}
	req.Close = false
	req.Header.Set("Range", "bytes=0-0")
	res, err := tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
	}()
	if res.StatusCode/100 != 2 {
		return 0, fmt.Errorf("failed to HEAD request with code %d", res.StatusCode)
	}
	contentRange := res.Header.Get("Content-Range")
	totalSize := strings.Split(contentRange, "/")[1]
	return strconv.ParseInt(totalSize, 10, 64)
}
