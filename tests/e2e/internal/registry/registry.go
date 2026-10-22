// Package registry runs an in-process OCI distribution registry behind a
// fault-injecting proxy, so registry-backed tests need no docker and can
// make the backend misbehave on cue.
package registry

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	ggcr "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Registry is a plain-HTTP registry on 127.0.0.1 holding blobs on disk.
type Registry struct {
	// Host is host:port, as image references use it.
	Host string
	// URL is the base URL including the scheme, as the nydus registry
	// backend's addr takes it.
	URL string
	// Faults is applied to every request.
	Faults *Faults
}

// Start starts a registry that lives until the test ends.
func Start(t env.TB) *Registry {
	t.Helper()
	faults := &Faults{}
	blobs := ggcr.NewDiskBlobHandler(t.TempDir())
	handler := ggcr.New(
		ggcr.Logger(log.New(io.Discard, "", 0)),
		ggcr.WithBlobHandler(blobs),
	)
	srv := httptest.NewServer(faults.Wrap(suffixRanges(blobs.(ggcr.BlobStatHandler), handler)))
	t.Cleanup(srv.Close)
	return &Registry{
		Host:   strings.TrimPrefix(srv.URL, "http://"),
		URL:    srv.URL,
		Faults: faults,
	}
}

// The registry library only supports explicit byte ranges. The backend
// discovers blob metadata with a suffix range, so normalize that form before
// handing the request to the library.
func suffixRanges(blobs ggcr.BlobStatHandler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix, ok := strings.CutPrefix(r.Header.Get("Range"), "bytes=-")
		if !ok || !IsBlobGet(r) {
			next.ServeHTTP(w, r)
			return
		}
		count, err := strconv.ParseInt(suffix, 10, 64)
		if err != nil || count <= 0 {
			http.Error(w, "invalid suffix range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		repo, digest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/"), "/blobs/")
		hash, err := v1.NewHash(digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		size, err := blobs.Stat(r.Context(), repo, hash)
		if err != nil {
			// Let the registry report its normal blob-not-found response.
			next.ServeHTTP(w, r)
			return
		}
		if size == 0 {
			w.Header().Set("Content-Range", "bytes */0")
			http.Error(w, "empty blob", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", max(0, size-count), size-1))
		next.ServeHTTP(w, r)
	})
}

// Ref returns the reference of repo:tag in this registry.
func (r *Registry) Ref(repo, tag string) string {
	return r.Host + "/" + repo + ":" + tag
}
