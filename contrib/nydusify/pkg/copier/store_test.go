package copier

import (
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type stubStore struct {
	infoFunc func(context.Context, digest.Digest) (content.Info, error)
}

func (s *stubStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	if s.infoFunc != nil {
		return s.infoFunc(ctx, dgst)
	}
	return content.Info{}, nil
}

func (s *stubStore) Update(context.Context, content.Info, ...string) (content.Info, error) {
	return content.Info{}, nil
}

func (s *stubStore) Walk(context.Context, content.WalkFunc, ...string) error { return nil }

func (s *stubStore) Delete(context.Context, digest.Digest) error { return nil }

func (s *stubStore) ReaderAt(context.Context, ocispec.Descriptor) (content.ReaderAt, error) {
	return nil, errdefs.ErrNotFound
}

func (s *stubStore) Status(context.Context, string) (content.Status, error) {
	return content.Status{}, nil
}

func (s *stubStore) ListStatuses(context.Context, ...string) ([]content.Status, error) {
	return nil, nil
}

func (s *stubStore) Abort(context.Context, string) error { return nil }

func (s *stubStore) Writer(context.Context, ...content.WriterOpt) (content.Writer, error) {
	return nil, errdefs.ErrNotImplemented
}
func TestStoreInfoFallsBackToRemoteDescriptors(t *testing.T) {
	testDigest := digest.FromString("remote")
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{}, errdefs.ErrNotFound
		},
	}

	store := newStore(base, []ocispec.Descriptor{{Digest: testDigest, Size: 128}})
	info, err := store.Info(context.Background(), testDigest)
	require.NoError(t, err)
	require.Equal(t, testDigest, info.Digest)
	require.EqualValues(t, 128, info.Size)
}

func TestStoreInfoPreservesUnexpectedError(t *testing.T) {
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{}, errdefs.ErrUnavailable
		},
	}

	store := newStore(base, nil)
	_, err := store.Info(context.Background(), digest.FromString("missing"))
	require.ErrorIs(t, err, errdefs.ErrUnavailable)
}

func TestStoreInfoReturnsBaseStoreInfoWhenPresent(t *testing.T) {
	testDigest := digest.FromString("base")
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{Digest: testDigest, Size: 64}, nil
		},
	}

	store := newStore(base, []ocispec.Descriptor{{Digest: testDigest, Size: 128}})
	info, err := store.Info(context.Background(), testDigest)
	require.NoError(t, err)
	require.Equal(t, testDigest, info.Digest)
	require.EqualValues(t, 64, info.Size)
}

func TestStoreInfoReturnsNotFoundWhenDigestMissingEverywhere(t *testing.T) {
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{}, errdefs.ErrNotFound
		},
	}

	store := newStore(base, nil)
	_, err := store.Info(context.Background(), digest.FromString("missing"))
	require.ErrorIs(t, err, errdefs.ErrNotFound)
}

func TestNewStoreDirectly(t *testing.T) {
	base := &stubStore{}
	descs := []ocispec.Descriptor{
		{Digest: digest.FromString("a"), Size: 10},
		{Digest: digest.FromString("b"), Size: 20},
	}
	s := newStore(base, descs)
	require.NotNil(t, s)
	require.Equal(t, base, s.Store)
	require.Len(t, s.remotes, 2)
}

func TestStoreInfoMultipleRemotes(t *testing.T) {
	targetDigest := digest.FromString("target")
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{}, errdefs.ErrNotFound
		},
	}
	store := newStore(base, []ocispec.Descriptor{
		{Digest: digest.FromString("a"), Size: 10},
		{Digest: targetDigest, Size: 200},
		{Digest: digest.FromString("c"), Size: 30},
	})

	info, err := store.Info(context.Background(), targetDigest)
	require.NoError(t, err)
	require.Equal(t, targetDigest, info.Digest)
	require.EqualValues(t, 200, info.Size)
}

func TestStoreInfoEmptyRemotes(t *testing.T) {
	base := &stubStore{
		infoFunc: func(context.Context, digest.Digest) (content.Info, error) {
			return content.Info{}, errdefs.ErrNotFound
		},
	}
	store := newStore(base, []ocispec.Descriptor{})
	_, err := store.Info(context.Background(), digest.FromString("missing"))
	require.ErrorIs(t, err, errdefs.ErrNotFound)
}
