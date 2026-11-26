// SPDX-License-Identifier: Apache-2.0
package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

func TestBlobStreamAbortAfterCancellation(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	location, err := url.Parse(server.URL + "/upload/session")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	upload := &BlobStreamUpload{
		ctx:      ctx,
		host:     docker.RegistryHost{Client: server.Client()},
		location: location,
	}
	upload.Abort()
	upload.Abort()
	if !upload.finished || deletes.Load() != 1 {
		t.Fatalf("finished=%v deletes=%d", upload.finished, deletes.Load())
	}
	if upload.ctx.Err() != context.Canceled {
		t.Fatal("cleanup replaced the original canceled context")
	}
}
