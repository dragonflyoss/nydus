// SPDX-License-Identifier: Apache-2.0
package pipeline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type cacheUpload interface {
	io.Writer
	Finish() (ocispec.Descriptor, error)
	Abort()
}

// Metadata-only layouts never open a registry upload session.
type lazyCacheUpload struct {
	ctx    context.Context
	open   func(context.Context) (cacheUpload, error)
	upload cacheUpload
}

func (u *lazyCacheUpload) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if u.upload == nil {
		var err error
		u.upload, err = u.open(u.ctx)
		if err != nil {
			return 0, err
		}
	}
	return u.upload.Write(data)
}
func (u *lazyCacheUpload) Finish() (ocispec.Descriptor, error) {
	if u.upload == nil {
		return ocispec.Descriptor{}, fmt.Errorf("builder emitted no blob bytes")
	}
	return u.upload.Finish()
}
func (u *lazyCacheUpload) Abort() {
	if u.upload != nil {
		u.upload.Abort()
	}
}

// EncodeCache streams a cache layout to the target registry without storing
// the encoded blob on disk. Artifact packaging validates bootstrap references.
func EncodeCache(ctx context.Context, opt nydus.EncodeOption, provider *remote.Provider, target string) (string, []UploadedBlob, error) {
	return encodeCache(ctx, opt, func(ctx context.Context) (cacheUpload, error) {
		return provider.NewBlobStreamUpload(ctx, target)
	})
}

func encodeCache(ctx context.Context, opt nydus.EncodeOption, openUpload func(context.Context) (cacheUpload, error)) (string, []UploadedBlob, error) {
	if _, err := os.Lstat(filepath.Join(opt.CacheDir, "image.json")); err == nil {
		return "", nil, fmt.Errorf("cache layout already has image.json")
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	upload := &lazyCacheUpload{ctx: ctx, open: openUpload}
	defer upload.Abort()
	if err := nydus.RunNydusEncode(ctx, opt, upload, cancel); err != nil {
		return "", nil, err
	}
	bootstrap := filepath.Join(opt.CacheDir, "image.boot")
	if err := checkCacheFile(bootstrap); err != nil {
		return "", nil, err
	}
	if upload.upload == nil {
		return bootstrap, nil, nil
	}
	desc, err := upload.Finish()
	if err != nil {
		return "", nil, err
	}
	if desc.Digest.Validate() != nil || desc.Digest.Algorithm() != digest.SHA256 || desc.Size <= 0 {
		return "", nil, fmt.Errorf("invalid encoded blob descriptor")
	}
	id := desc.Digest.Encoded()
	for _, suffix := range []string{".blob.data", ".blob.meta", ".group.map"} {
		if err := checkCacheFile(filepath.Join(opt.CacheDir, id+suffix)); err != nil {
			return "", nil, err
		}
	}
	return bootstrap, []UploadedBlob{{Digest: desc.Digest, Size: desc.Size, MetadataPath: filepath.Join(opt.CacheDir, id+".blob.meta")}}, nil
}

func checkCacheFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cache layout output is not a regular file: %s", path)
	}
	return nil
}
