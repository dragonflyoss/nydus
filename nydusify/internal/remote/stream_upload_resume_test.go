package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

func TestStreamUploadRecoversAcknowledgedOffsets(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		for _, accepted := range []int{0, 1, 73, streamUploadChunkSize} {
			t.Run(fmt.Sprintf("accepted=%d/disconnect=%t", accepted, disconnect), func(t *testing.T) {
				var received bytes.Buffer
				failed, queries := false, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", "/v2/snapshot/blobs/uploads/session")
					if received.Len() > 0 {
						w.Header().Set("Range", fmt.Sprintf("0-%d", received.Len()-1))
					} else {
						w.Header().Set("Range", "0-0")
					}
					switch r.Method {
					case http.MethodPost:
						w.WriteHeader(http.StatusAccepted)
					case http.MethodGet:
						queries++
						w.WriteHeader(http.StatusNoContent)
					case http.MethodPatch:
						wantRange := fmt.Sprintf("%d-%d", received.Len(), received.Len()+int(r.ContentLength)-1)
						if r.Header.Get("Content-Range") != wantRange {
							w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
							return
						}
						data, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
							return
						}
						if !failed {
							received.Write(data[:accepted])
							failed = true
							if disconnect {
								connection, _, err := w.(http.Hijacker).Hijack()
								if err != nil {
									t.Error(err)
									return
								}
								_ = connection.Close()
								return
							}
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						received.Write(data)
						w.Header().Set("Range", fmt.Sprintf("0-%d", received.Len()-1))
						w.WriteHeader(http.StatusAccepted)
					case http.MethodPut:
						if r.URL.Query().Get("digest") != digest.FromBytes(received.Bytes()).String() {
							t.Error("corrupt resumed blob")
						}
						w.WriteHeader(http.StatusCreated)
					case http.MethodDelete:
						w.WriteHeader(http.StatusNoContent)
					}
				}))
				defer server.Close()
				parsed, _ := url.Parse(server.URL)
				provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
				if err != nil {
					t.Fatal(err)
				}
				upload, err := provider.NewBlobStreamUpload(context.Background(), parsed.Host+"/snapshot:latest")
				if err != nil {
					t.Fatal(err)
				}
				defer upload.Abort()
				input := bytes.Repeat([]byte("abcdefgh"), streamUploadChunkSize/8)
				if _, err := upload.Write(input); err != nil {
					t.Fatal(err)
				}
				if _, err := upload.Finish(); err != nil {
					t.Fatal(err)
				}
				if queries == 0 || !bytes.Equal(input, received.Bytes()) {
					t.Fatal("resume did not preserve payload")
				}
			})
		}
	}
}

func TestStreamUploadRespectsMinimumWhenResuming(t *testing.T) {
	const minimum = streamUploadChunkSize + 1024
	for _, tc := range []struct {
		name          string
		size          int
		acceptedPatch int
		acceptedPut   int
		wantPatches   int
	}{
		{"empty-first-patch", minimum + 17, 0, -1, 2},
		{"one-byte-first-patch", minimum, 1, -1, 2},
		{"coalesce-partial-patch", minimum + 137, 73, -1, 2},
		{"partial-final-put", minimum, minimum - 17, 3, 1},
		{"one-byte-final-put", 17, -1, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern := []byte("0123456789abcdef")
			input := bytes.Repeat(pattern, (tc.size+len(pattern)-1)/len(pattern))[:tc.size]
			wantDigest := digest.FromBytes(input)
			var received bytes.Buffer
			patches, queries := 0, 0
			failedPut := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/upload")
				w.Header().Set("Range", fmt.Sprintf("0-%d", max(0, received.Len()-1)))
				switch r.Method {
				case http.MethodPost:
					w.Header().Set("OCI-Chunk-Min-Length", strconv.Itoa(minimum))
					w.WriteHeader(http.StatusAccepted)
				case http.MethodGet:
					queries++
					w.WriteHeader(http.StatusNoContent)
				case http.MethodHead:
					w.WriteHeader(http.StatusNotFound)
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				case http.MethodPatch, http.MethodPut:
					if r.Method == http.MethodPatch {
						patches++
						if r.ContentLength < minimum {
							t.Errorf("undersized PATCH: %d < %d", r.ContentLength, minimum)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
					}
					if r.ContentLength > 0 {
						start := int64(received.Len())
						if r.Header.Get("Content-Range") != fmt.Sprintf("%d-%d", start, start+r.ContentLength-1) {
							w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
							return
						}
					}
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if r.Method == http.MethodPatch {
						if patches == 1 && tc.acceptedPatch >= 0 {
							received.Write(data[:tc.acceptedPatch])
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						received.Write(data)
						w.Header().Set("Range", fmt.Sprintf("0-%d", received.Len()-1))
						w.WriteHeader(http.StatusAccepted)
						return
					}
					if !failedPut && tc.acceptedPut >= 0 {
						failedPut = true
						received.Write(data[:tc.acceptedPut])
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					received.Write(data)
					if r.URL.Query().Get("digest") != wantDigest.String() || !bytes.Equal(input, received.Bytes()) {
						t.Error("final PUT did not commit the original payload")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusCreated)
				default:
					t.Error("unexpected method", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()

			provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			upload, err := provider.NewBlobStreamUpload(context.Background(), strings.TrimPrefix(server.URL, "http://")+"/snapshot:latest")
			if err != nil {
				t.Fatal(err)
			}
			defer upload.Abort()
			if _, err := upload.Write(input); err != nil {
				t.Fatal(err)
			}
			desc, err := upload.Finish()
			if err != nil || desc.Digest != wantDigest || desc.Size != int64(len(input)) {
				t.Fatalf("finish returned %+v, %v", desc, err)
			}
			if patches != tc.wantPatches || queries == 0 {
				t.Fatalf("unexpected request counts: PATCH=%d, GET=%d", patches, queries)
			}
		})
	}
}

func TestStreamUploadRecoversCommit(t *testing.T) {
	payload := []byte("encoded snapshot")
	dgst := digest.FromBytes(payload)
	for _, mode := range []string{"committed", "retry", "wrong-size"} {
		t.Run(mode, func(t *testing.T) {
			patches, puts, heads := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPost:
					w.Header().Set("Location", "/session")
					w.WriteHeader(http.StatusAccepted)
				case http.MethodPatch:
					patches++
					w.Header().Set("Location", "/session")
					w.WriteHeader(http.StatusAccepted)
				case http.MethodPut:
					puts++
					if r.URL.Query().Get("digest") != dgst.String() || r.ContentLength != 0 {
						t.Error("unexpected commit request")
					}
					if puts == 1 && mode == "committed" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
					if puts == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
					} else {
						w.WriteHeader(http.StatusCreated)
					}
				case http.MethodHead:
					heads++
					if r.URL.Path != "/v2/snapshot/blobs/"+dgst.String() {
						t.Error("checked the wrong blob URL", r.URL.Path)
					}
					if mode == "retry" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					size := len(payload)
					if mode == "wrong-size" {
						size++
					}
					w.Header().Set("Content-Length", strconv.Itoa(size))
					w.Header().Set("Docker-Content-Digest", dgst.String())
					w.WriteHeader(http.StatusOK)
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("unexpected method", r.Method)
				}
			}))
			defer server.Close()
			provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			upload, err := provider.NewBlobStreamUpload(context.Background(), strings.TrimPrefix(server.URL, "http://")+"/snapshot:latest")
			if err != nil {
				t.Fatal(err)
			}
			defer upload.Abort()
			if _, err := upload.Write(payload); err != nil {
				t.Fatal(err)
			}
			desc, err := upload.Finish()
			if mode == "wrong-size" {
				if err == nil || !strings.Contains(err.Error(), "blob size") {
					t.Fatalf("accepted a mismatched blob: %v", err)
				}
			} else if err != nil || desc.Digest != dgst || desc.Size != int64(len(payload)) {
				t.Fatalf("commit recovery returned %+v, %v", desc, err)
			}
			wantPuts := 1
			if mode == "retry" {
				wantPuts++
			}
			if patches != 1 || puts != wantPuts || heads != 1 {
				t.Fatalf("unexpected request counts: PATCH=%d PUT=%d HEAD=%d", patches, puts, heads)
			}
		})
	}
}

func TestStreamUploadNegotiatesMinimumChunk(t *testing.T) {
	for _, minimum := range []string{strconv.Itoa(2 * streamUploadChunkSize), "invalid", "0", "4294967295"} {
		t.Run(minimum, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/upload")
				switch r.Method {
				case http.MethodPost:
					w.Header().Set("OCI-Chunk-Min-Length", minimum)
					w.WriteHeader(http.StatusAccepted)
				case http.MethodPatch:
					if r.ContentLength != 2*streamUploadChunkSize || r.Header.Get("Content-Range") != fmt.Sprintf("0-%d", 2*streamUploadChunkSize-1) {
						t.Error("minimum chunk ignored")
					}
					_, _ = io.Copy(io.Discard, r.Body)
					w.WriteHeader(http.StatusAccepted)
				case http.MethodPut:
					w.WriteHeader(http.StatusCreated)
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			upload, err := provider.NewBlobStreamUpload(context.Background(), parsed.Host+"/snapshot:latest")
			if minimum != strconv.Itoa(2*streamUploadChunkSize) {
				if err == nil {
					upload.Abort()
					t.Fatal("unbounded or invalid minimum accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer upload.Abort()
			if _, err := io.Copy(upload, strings.NewReader(strings.Repeat("x", 2*streamUploadChunkSize))); err != nil {
				t.Fatal(err)
			}
			if _, err := upload.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
