package provider

import (
	"context"
	"testing"

	ctrcontent "github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestStreamContentWriterAndReaderFromMemory(t *testing.T) {
	sc := NewStreamContent(nil, nil)
	desc := ocispec.Descriptor{Digest: digest.FromBytes([]byte("descriptor"))}

	writer, err := sc.Writer(context.Background(), ctrcontent.WithDescriptor(desc), ctrcontent.WithRef("generated-json"))
	require.NoError(t, err)

	written, err := writer.Write([]byte("payload"))
	require.NoError(t, err)
	require.Equal(t, len("payload"), written)

	status, err := writer.Status()
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), status.Offset)
	require.EqualValues(t, len("payload"), status.Total)

	require.NoError(t, writer.Commit(context.Background(), 0, ""))

	reader, err := sc.ReaderAt(context.Background(), ocispec.Descriptor{Digest: writer.Digest()})
	require.NoError(t, err)
	defer reader.Close()

	buf := make([]byte, len("payload"))
	read, err := reader.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, len(buf), read)
	require.Equal(t, "payload", string(buf))
	require.EqualValues(t, len("payload"), reader.Size())
}

func TestStreamContentWriterReturnsAlreadyExistsForFetchRefs(t *testing.T) {
	sc := NewStreamContent(nil, nil)
	for _, ref := range []string{"manifest-sha256:test", "index-sha256:test", "layer-sha256:test", "config-sha256:test", "attestation-sha256:test"} {
		t.Run(ref, func(t *testing.T) {
			writer, err := sc.Writer(context.Background(), ctrcontent.WithRef(ref))
			require.ErrorIs(t, err, errdefs.ErrAlreadyExists)
			require.Nil(t, writer)
		})
	}
}

func TestStreamContentReaderAtWithoutDefaultRef(t *testing.T) {
	sc := NewStreamContent(nil, nil)
	_, err := sc.ReaderAt(context.Background(), ocispec.Descriptor{Digest: digest.FromString("missing")})
	require.Error(t, err)
	require.ErrorIs(t, err, errdefs.ErrNotFound)
	require.ErrorContains(t, err, "defaultRef is empty")
}

func TestStreamContentInfoUpdateAndDelete(t *testing.T) {
	sc := NewStreamContent(nil, nil)
	dgst := digest.FromString("labels")

	info, err := sc.Info(context.Background(), dgst)
	require.NoError(t, err)
	require.Equal(t, dgst, info.Digest)
	require.Nil(t, info.Labels)

	updated, err := sc.Update(context.Background(), ctrcontent.Info{Digest: dgst, Labels: map[string]string{"containerd.io/distribution.source": "repo"}})
	require.NoError(t, err)
	require.Equal(t, "repo", updated.Labels["containerd.io/distribution.source"])

	updated.Labels["containerd.io/distribution.source"] = "mutated"
	info, err = sc.Info(context.Background(), dgst)
	require.NoError(t, err)
	require.Equal(t, "repo", info.Labels["containerd.io/distribution.source"])

	require.NoError(t, sc.Delete(context.Background(), dgst))
	info, err = sc.Info(context.Background(), dgst)
	require.NoError(t, err)
	require.Nil(t, info.Labels)
}

func TestStreamContentHelpers(t *testing.T) {
	require.Nil(t, copyMap(nil))
	require.False(t, isFetchRef(""))
	require.False(t, isFetchRef("other-sha256:test"))
	require.True(t, isFetchRef("manifest-sha256:test"))
	require.True(t, hasPrefix("manifest-sha256:test", "manifest-"))
	require.False(t, hasPrefix("man", "manifest-"))

	sc := NewStreamContent(nil, nil)
	sc.SetDefaultRef("example.com/repo:tag")
	sc.mu.RLock()
	require.Equal(t, "example.com/repo:tag", sc.defaultRef)
	sc.mu.RUnlock()
}

func TestMemWriterTruncateAndCommitWithExpectedDigest(t *testing.T) {
	sc := NewStreamContent(nil, nil)
	writer := newMemWriter(sc, ocispec.Descriptor{})

	_, err := writer.Write([]byte("payload"))
	require.NoError(t, err)
	originalDigest := writer.Digest()
	require.NoError(t, writer.Truncate(4))
	require.Equal(t, originalDigest, writer.Digest())
	require.Error(t, writer.Truncate(-1))

	expected := digest.FromString("expected")
	require.NoError(t, writer.Commit(context.Background(), 0, expected))

	reader, err := sc.ReaderAt(context.Background(), ocispec.Descriptor{Digest: expected})
	require.NoError(t, err)
	defer reader.Close()

	buf := make([]byte, 4)
	_, err = reader.ReadAt(buf, 0)
	require.NoError(t, err)
	require.Equal(t, "payl", string(buf))
}
