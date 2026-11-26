/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

func TestBlobStreamUploadUsesBoundedPatchesAndFinalDigest(t *testing.T) {
	var received bytes.Buffer
	patches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "secret" {
			w.Header().Set("WWW-Authenticate", "Basic realm=stream-test")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != "/v2/snapshot/blobs/uploads/" {
				t.Errorf("POST path = %q", r.URL.Path)
			}
			w.Header().Set("Location", "/v2/snapshot/blobs/uploads/session")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPatch:
			patches++
			if r.ContentLength < 0 || r.ContentLength > streamUploadChunkSize {
				t.Errorf("unbounded PATCH content length = %d", r.ContentLength)
			}
			if _, err := io.Copy(&received, r.Body); err != nil {
				t.Errorf("read PATCH: %v", err)
			}
			w.Header().Set("Location", "/v2/snapshot/blobs/uploads/session")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPut:
			want := digest.FromBytes(received.Bytes())
			if got := r.URL.Query().Get("digest"); got != want.String() {
				t.Errorf("final digest = %q, want %s", got, want)
			}
			w.Header().Set("Docker-Content-Digest", want.String())
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(Option{
		WorkDir:         t.TempDir(),
		TargetPlainHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.credFunc = func(string) (string, string, error) {
		return "user", "secret", nil
	}
	upload, err := provider.NewBlobStreamUpload(context.Background(), u.Host+"/snapshot:latest")
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Abort()

	data := append(bytes.Repeat([]byte("a"), streamUploadChunkSize), []byte("tail")...)
	if _, err := io.Copy(upload, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	desc, err := upload.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if patches != 2 || desc.Size != int64(len(data)) || desc.Digest != digest.FromBytes(data) {
		t.Fatalf("patches = %d, descriptor = %+v", patches, desc)
	}
	if _, err := provider.ContentStore().Info(context.Background(), desc.Digest); err == nil {
		t.Fatal("upload unexpectedly wrote a local content-store blob")
	}
}
