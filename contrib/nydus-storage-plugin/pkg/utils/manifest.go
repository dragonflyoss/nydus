// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/6fb41553e735eb6369bb3718d4b841bfacb423aa/util/containerdutil/manifest.go#L119-L158
package utils

import (
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Forked from github.com/containerd/containerd/images/image.go
// commit: a776a27af54a803657d002e7574a4425b3949f56

// unknownDocument represents a manifest, manifest list, or index that has not
// yet been validated.
type unknownDocument struct {
	MediaType string          `json:"mediaType,omitempty"`
	Config    json.RawMessage `json:"config,omitempty"`
	Layers    json.RawMessage `json:"layers,omitempty"`
	Manifests json.RawMessage `json:"manifests,omitempty"`
	FSLayers  json.RawMessage `json:"fsLayers,omitempty"` // schema 1
}

// ValidateMediaType returns an error if the byte slice is invalid JSON or if
// the media type identifies the blob as one format but it contains elements of
// another format.
func ValidateMediaType(b []byte, mt string) error {
	var doc unknownDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.FSLayers) != 0 {
		return fmt.Errorf("media-type: schema 1 not supported")
	}
	switch mt {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		if len(doc.Manifests) != 0 ||
			doc.MediaType == images.MediaTypeDockerSchema2ManifestList ||
			doc.MediaType == ocispec.MediaTypeImageIndex {
			return fmt.Errorf("media-type: expected manifest but found index (%s)", mt)
		}
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		if len(doc.Config) != 0 || len(doc.Layers) != 0 ||
			doc.MediaType == images.MediaTypeDockerSchema2Manifest ||
			doc.MediaType == ocispec.MediaTypeImageManifest {
			return fmt.Errorf("media-type: expected index but found manifest (%s)", mt)
		}
	}
	return nil
}
