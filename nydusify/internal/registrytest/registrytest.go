/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package registrytest provides an in-memory OCI distribution registry for
// tests, in the manner of net/http/httptest.
package registrytest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

// Registry is an in-memory OCI distribution registry served over plain HTTP.
// It answers the API version check, manifest HEAD, GET and PUT, blob HEAD and
// GET with Range, monolithic blob uploads and cross-repository blob mounts.
type Registry struct {
	// Host is the host:port the registry listens on.
	Host string

	// username and password are the basic auth credentials required on
	// every request when username is set.
	username, password string

	// mu guards content, tags, uploads and requests.
	mu sync.Mutex

	// content maps repo@digest to the stored content.
	content map[string]object

	// tags maps repo:tag to a manifest digest.
	tags map[string]digest.Digest

	// uploads counts the upload sessions started.
	uploads int

	// requests lists every request received, in order.
	requests []Request
}

// object is a stored blob or manifest.
type object struct {
	// mediaType is the manifest media type, empty for a plain blob.
	mediaType string

	// data is the raw content.
	data []byte
}

// Request is a request received by a Registry.
type Request struct {
	// Method is the HTTP method.
	Method string

	// URL is the request URL, path and query.
	URL string
}

// Option configures a Registry.
type Option func(*Registry)

// WithBasicAuth makes the registry answer 401 with a Basic challenge to every
// request that does not carry username and password.
func WithBasicAuth(username, password string) Option {
	return func(r *Registry) {
		r.username, r.password = username, password
	}
}

// New starts a Registry that is closed when t and its subtests complete.
func New(t testing.TB, opts ...Option) *Registry {
	r := &Registry{content: map[string]object{}, tags: map[string]digest.Digest{}}
	for _, opt := range opts {
		opt(r)
	}

	server := httptest.NewServer(http.HandlerFunc(r.serveHTTP))
	t.Cleanup(server.Close)
	r.Host = strings.TrimPrefix(server.URL, "http://")
	return r
}

// Forbidding starts a server that answers 403 to every request, closed when t
// and its subtests complete, and returns its host:port.
func Forbidding(t testing.TB) string {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

// Ref returns the reference to tag in repo.
func (r *Registry) Ref(repo, tag string) string {
	return r.Host + "/" + repo + ":" + tag
}

// Store stores data in repo and returns its descriptor. Data stored with a
// media type is also served as a manifest, and tag, unless empty or a digest,
// is pointed at it.
func (r *Registry) Store(repo, tag, mediaType string, data []byte) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.content[repo+"@"+desc.Digest.String()] = object{mediaType: mediaType, data: data}
	if tag != "" && digest.Digest(tag).Validate() != nil {
		r.tags[repo+":"+tag] = desc.Digest
	}

	return desc
}

// StoreJSON stores v encoded as JSON like Store, failing t if v cannot be
// encoded.
func (r *Registry) StoreJSON(t testing.TB, repo, tag, mediaType string, v any) ocispec.Descriptor {
	t.Helper()
	data, err := json.Marshal(v)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return r.Store(repo, tag, mediaType, data)
}

// Load returns the content that reference, a tag or a digest, names in repo
// and reports whether it exists.
func (r *Registry) Load(repo, reference string) ([]byte, bool) {
	content, _, ok := r.load(repo, reference)
	return content.data, ok
}

// LoadJSON decodes the content that reference, a tag or a digest, names in
// repo into v, failing t if it is missing or not valid JSON.
func (r *Registry) LoadJSON(t testing.TB, repo, reference string, v any) {
	t.Helper()
	data, ok := r.Load(repo, reference)
	if !assert.True(t, ok, "%s@%s not found", repo, reference) || !assert.NoError(t, json.Unmarshal(data, v)) {
		t.FailNow()
	}
}

// Requests returns the requests received so far, in order.
func (r *Registry) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.requests)
}

// load resolves reference in repo to its content and digest.
func (r *Registry) load(repo, reference string) (object, digest.Digest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dgst, ok := r.tags[repo+":"+reference]
	if !ok {
		dgst = digest.Digest(reference)
	}

	content, ok := r.content[repo+"@"+dgst.String()]
	return content, dgst, ok
}

// serveHTTP routes a distribution API request.
func (r *Registry) serveHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, Request{Method: req.Method, URL: req.URL.String()})
	r.mu.Unlock()
	if username, password, ok := req.BasicAuth(); r.username != "" && (!ok || username != r.username || password != r.password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registrytest"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	path := strings.TrimPrefix(req.URL.Path, "/v2/")
	if repo, _, ok := strings.Cut(path, "/blobs/uploads/"); ok {
		r.serveUpload(w, req, repo)
		return
	}

	if repo, reference, ok := strings.Cut(path, "/manifests/"); ok {
		r.serveManifest(w, req, repo, reference)
		return
	}

	if repo, dgst, ok := strings.Cut(path, "/blobs/"); ok {
		r.serveBlob(w, req, repo, dgst)
		return
	}

	if path != "" {
		w.WriteHeader(http.StatusNotFound)
	}
}

// serveUpload mounts a blob from another repository or starts and completes
// a monolithic upload.
func (r *Registry) serveUpload(w http.ResponseWriter, req *http.Request, repo string) {
	switch req.Method {
	case http.MethodPost:
		mount, from := req.URL.Query().Get("mount"), req.URL.Query().Get("from")
		r.mu.Lock()
		defer r.mu.Unlock()
		if blob, ok := r.content[from+"@"+mount]; ok && mount != "" {
			r.content[repo+"@"+mount] = blob
			w.Header().Set("Docker-Content-Digest", mount)
			w.WriteHeader(http.StatusCreated)
			return
		}

		r.uploads++
		w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+strconv.Itoa(r.uploads))
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		data, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		dgst := digest.Digest(req.URL.Query().Get("digest"))
		if digest.FromBytes(data) != dgst {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		r.Store(repo, "", "", data)
		w.Header().Set("Docker-Content-Digest", dgst.String())
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// serveManifest stores a pushed manifest or serves a stored one.
func (r *Registry) serveManifest(w http.ResponseWriter, req *http.Request, repo, reference string) {
	if req.Method == http.MethodPut {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		desc := r.Store(repo, reference, req.Header.Get("Content-Type"), data)
		w.Header().Set("Docker-Content-Digest", desc.Digest.String())
		w.WriteHeader(http.StatusCreated)
		return
	}

	content, dgst, ok := r.load(repo, reference)
	if !ok || content.mediaType == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", content.mediaType)
	w.Header().Set("Docker-Content-Digest", dgst.String())
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(content.data))
}

// serveBlob serves a stored blob, honoring Range.
func (r *Registry) serveBlob(w http.ResponseWriter, req *http.Request, repo, reference string) {
	content, dgst, ok := r.load(repo, reference)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", dgst.String())
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(content.data))
}
