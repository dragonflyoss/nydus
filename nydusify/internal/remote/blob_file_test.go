package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestPushBlobFile(t *testing.T) {
	data := []byte("local artifact blob")
	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data))}
	pusher := &contentTestPusher{}

	err := pushBlobFile(
		context.Background(),
		contentTestResolver{pusher: pusher},
		desc,
		"example.test/image:tag",
		path,
	)
	require.NoError(t, err)
	require.Len(t, pusher.writers, 1)
	require.Equal(t, data, pusher.writers[0].Bytes())
	require.Equal(t, 1, pusher.writers[0].commits)
	require.Equal(t, 1, pusher.writers[0].closes)
}

func TestPushBlobFileSkipsExistingRemote(t *testing.T) {
	data := []byte("existing blob")
	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	desc := ocispec.Descriptor{Digest: digest.FromBytes(data), Size: int64(len(data))}
	pusher := &contentTestPusher{pushErr: errdefs.ErrAlreadyExists}

	err := pushBlobFile(
		context.Background(),
		contentTestResolver{pusher: pusher},
		desc,
		"example.test/image:tag",
		path,
	)
	require.NoError(t, err)
	require.Empty(t, pusher.writers)
}
