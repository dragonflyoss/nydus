package backend

import (
	"context"
	"os"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type Registry struct {
	remote *remote.Remote
}

func (r *Registry) Upload(
	ctx context.Context, blobID, blobPath string, size int64, forcePush bool,
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

func (r *Registry) Check(blobID string) (bool, error) {

	return true, nil
}

func (r *Registry) Type() BackendType {
	return RegistryBackend
}

func newRegistryBackend(rawConfig []byte, remote *remote.Remote) (Backend, error) {
	return &Registry{remote: remote}, nil
}
