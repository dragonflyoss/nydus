package backend

import (
	"context"
	"io"
	"os"

	"github.com/containerd/containerd/v2/core/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
)

type Registry struct {
	remote *remote.Remote
}

func (r *Registry) Upload(
	ctx context.Context, blobID, blobPath string, size int64, _ bool,
) (*ocispec.Descriptor, error) {
	// The `forcePush` option is useless for registry backend, because
	// the blob existed in registry can't be pushed again.

	desc := blobDesc(size, blobID)

	blobFile, err := os.Open(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "Open blob file")
	}
	defer blobFile.Close()

	if err := r.remote.Push(ctx, desc, true, blobFile); err != nil {
		return nil, errors.Wrap(err, "Push blob layer")
	}

	return &desc, nil
}

func (r *Registry) Finalize(_ bool) error {
	return nil
}

func (r *Registry) Check(_ string) (bool, error) {
	return true, nil
}

func (r *Registry) Type() Type {
	return RegistryBackend
}

func (r *Registry) RangeReader(_ string) (remotes.RangeReadCloser, error) {
	panic("not implemented")
}

func (r *Registry) Reader(_ string) (io.ReadCloser, error) {
	panic("not implemented")
}

func (r *Registry) Size(_ string) (int64, error) {
	panic("not implemented")
}

func newRegistryBackend(_ []byte, remote *remote.Remote) (Backend, error) {
	return &Registry{remote: remote}, nil
}
