package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// PrepareCacheRepack reuses the artifact backend for parent range reads.
// The provisional upper device is read directly from cache.data by Rust.
func PrepareCacheRepack(ctx context.Context, opt ArtifactOption, parentCacheDir string) (string, func(), error) {
	// A cache layout adds at most one upper blob. Pruning can only lower this
	// bound, so do not stage metadata or require a reader when it fits.
	sourceBlobCount := 1
	for _, parent := range opt.ParentImages {
		sourceBlobCount += len(parent.Blobs)
	}
	if opt.CompactMaxLayers == 0 || uint(sourceBlobCount) <= opt.CompactMaxLayers {
		return "", func() {}, nil
	}
	if opt.OpenCompactBlob == nil {
		return "", nil, fmt.Errorf("cache layout compaction requires a parent blob reader")
	}
	if err := os.MkdirAll(opt.WorkDir, 0700); err != nil {
		return "", nil, err
	}
	work, err := os.MkdirTemp(opt.WorkDir, "cache-repack-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	blobs := filepath.Join(work, "blobs")
	if err := os.Mkdir(blobs, 0700); err != nil {
		cleanup()
		return "", nil, err
	}
	var descs []ocispec.Descriptor
	var metas []nydus.BlobMetaFile
	for _, parent := range opt.ParentImages {
		descs = append(descs, parent.Blobs...)
		metas = append(metas, parent.BlobMetas...)
	}
	if err := stageRepackBlobs(opt, descs, nil, blobs, metas); err != nil {
		cleanup()
		return "", nil, err
	}
	config, closeBackend, err := startRepackBackend(ctx, opt, blobs, work, parentCacheDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return config, func() { closeBackend(); cleanup() }, nil
}

// Serve only digests staged by the preparation callback. Auth and TLS stay in
// containerd's resolver; Rust reuses its registry range reader over loopback.
func startRepackBackend(ctx context.Context, opt ArtifactOption, blobs, work, cacheDir string) (string, func(), error) {
	if cacheDir == "" {
		cacheDir = filepath.Join(work, "output", "cache")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", nil, err
	}
	repository := "repack-" + hex.EncodeToString(token[:])
	prefix := "/v2/" + repository + "/blobs/sha256:"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimPrefix(r.URL.Path, prefix)
			if (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
				id == r.URL.Path || !isSha256Hex(id) {
				http.NotFound(w, r)
				return
			}
			path := filepath.Join(blobs, id)
			var reader io.ReadSeekCloser
			if file, err := os.Open(path); err == nil {
				reader = file
			} else if !os.IsNotExist(err) {
				http.Error(w, "open local compact blob", http.StatusInternalServerError)
				return
			} else {
				data, err := os.ReadFile(path + ".descriptor.json")
				var desc ocispec.Descriptor
				if err != nil || json.Unmarshal(data, &desc) != nil ||
					desc.Digest != digest.NewDigestFromEncoded(digest.SHA256, id) || desc.Size < 0 || opt.OpenCompactBlob == nil {
					http.NotFound(w, r)
					return
				}
				reader, err = opt.OpenCompactBlob(r.Context(), desc, r.Header.Get("Range"))
				if err != nil {
					http.Error(w, "open registry compact blob", http.StatusBadGateway)
					return
				}
			}
			defer func() { _ = reader.Close() }()
			// Prevent ServeContent's type-sniffing read at offset zero.
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, id, time.Time{}, reader)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	closeServer := func() { _ = server.Close() }
	config := map[string]any{
		"backend": map[string]any{"type": "registry", "config": map[string]any{
			"addr": "http://" + listener.Addr().String(), "repository": repository,
		}},
		"storage":  map[string]any{"dir": cacheDir},
		"prefetch": map[string]any{"scope": "none"},
	}
	data, err := json.Marshal(config)
	if err != nil {
		closeServer()
		return "", nil, err
	}
	path := filepath.Join(work, "backend.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		closeServer()
		return "", nil, err
	}
	return path, closeServer, nil
}
