package remote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
			response, err := upload.request(http.MethodPatch, address, []byte("data"), http.StatusAccepted, false)
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

type uploadErrorTransport struct{ err error }

func (tr uploadErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "storage.invalid" {
		return nil, tr.err
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestUploadErrorsRedactSignedLocations(t *testing.T) {
	const signed = "https://synthetic-user:synthetic-password@storage.invalid/blob?signature=synthetic-signature#synthetic-fragment"
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect=%t", redirect), func(t *testing.T) {
			location, err := url.Parse(signed)
			if err != nil {
				t.Fatal(err)
			}
			transportError := &url.Error{Op: "write", URL: signed, Err: context.DeadlineExceeded}
			client := &http.Client{Transport: uploadErrorTransport{err: transportError}}
			if redirect {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, signed, http.StatusTemporaryRedirect)
				}))
				defer origin.Close()
				location, err = url.Parse(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
			}
			upload := &BlobStreamUpload{ctx: context.Background(), host: docker.RegistryHost{Client: client}}
			response, err := upload.request(http.MethodPatch, location, []byte("data"), http.StatusAccepted, false)
			if response != nil {
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lost transport cause: %v", err)
			}
			var urlError *url.Error
			if !errors.As(err, &urlError) || !urlError.Timeout() {
				t.Fatalf("lost typed timeout: %v", err)
			}
			for _, secret := range []string{"synthetic-user", "synthetic-password", "synthetic-signature", "synthetic-fragment", "signature="} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("upload error contains URL credentials: %v", err)
				}
			}
			if !strings.Contains(err.Error(), "storage.invalid/blob") {
				t.Fatalf("lost safe location context: %v", err)
			}
			if transportError.URL != signed {
				t.Fatal("mutated shared transport error")
			}
		})
	}
}

func TestUploadLocationParseErrorRedactsSignedLocation(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "http://registry.invalid/upload", nil)
	if err != nil {
		t.Fatal(err)
	}
	upload := &BlobStreamUpload{}
	err = upload.advance(&http.Response{
		Request: request,
		Header:  http.Header{"Location": {":invalid?signature=synthetic-signature"}},
	})
	if err == nil || strings.Contains(err.Error(), "signature") {
		t.Fatalf("invalid upload location was not redacted: %v", err)
	}
	if upload.location != nil {
		t.Fatal("invalid location changed upload state")
	}
}
