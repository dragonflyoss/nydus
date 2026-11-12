package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

type uploadTestAuthorizer struct{}

func (uploadTestAuthorizer) Authorize(_ context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer synthetic-test-only")
	return nil
}
func (uploadTestAuthorizer) AddResponses(context.Context, []*http.Response) error { return nil }

func TestUploadRedirectCredentialBoundary(t *testing.T) {
	for _, mode := range []string{"same-origin", "other-port", "tls-downgrade", "custom-policy", "loop"} {
		t.Run(mode, func(t *testing.T) {
			seen := make(chan http.Header, 1)
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				w.WriteHeader(http.StatusAccepted)
			}))
			defer destination.Close()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/done" {
					seen <- r.Header.Clone()
					w.WriteHeader(http.StatusAccepted)
					return
				}
				location := destination.URL
				if mode == "same-origin" {
					location = "/done"
				}
				if mode == "loop" {
					location = "/loop"
				}
				http.Redirect(w, r, location, http.StatusTemporaryRedirect)
			})
			origin := httptest.NewUnstartedServer(handler)
			if mode == "tls-downgrade" {
				origin.StartTLS()
			} else {
				origin.Start()
			}
			defer origin.Close()
			address, _ := url.Parse(origin.URL)
			client := origin.Client()
			policyError := errors.New("redirect rejected by caller")
			if mode == "custom-policy" {
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return policyError }
			}
			upload := &BlobStreamUpload{ctx: context.Background(), host: docker.RegistryHost{
				Host: address.Host, Scheme: address.Scheme, Client: client, Authorizer: uploadTestAuthorizer{},
				Header: http.Header{"X-Registry-Secret": {"synthetic"}},
			}}
			response, err := upload.request(http.MethodPatch, address, []byte("data"), http.StatusAccepted)
			if mode == "custom-policy" || mode == "loop" {
				if err == nil {
					t.Fatal("redirect policy not enforced")
				}
				if mode == "custom-policy" && !errors.Is(err, policyError) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			headers := <-seen
			want := mode == "same-origin"
			if (headers.Get("Authorization") != "") != want || (headers.Get("X-Registry-Secret") != "") != want {
				t.Fatal("redirect crossed credential boundary")
			}
			// Upload policy must not mutate the shared registry client.
			if client.CheckRedirect != nil && mode != "custom-policy" {
				t.Fatal("shared client modified")
			}
		})
	}
}
