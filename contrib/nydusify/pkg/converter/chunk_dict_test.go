package converter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseChunkDictArgs(t *testing.T) {
	t.Run("registry reference keeps trailing colons", func(t *testing.T) {
		format, source, ref, err := ParseChunkDictArgs("bootstrap:registry:docker.io/library/busybox:latest")
		require.NoError(t, err)
		require.Equal(t, "bootstrap", format)
		require.Equal(t, "registry", source)
		require.Equal(t, "docker.io/library/busybox:latest", ref)
	})

	t.Run("local path is supported", func(t *testing.T) {
		format, source, ref, err := ParseChunkDictArgs("bootstrap:local:/var/lib/nydus/bootstrap")
		require.NoError(t, err)
		require.Equal(t, "bootstrap", format)
		require.Equal(t, "local", source)
		require.Equal(t, "/var/lib/nydus/bootstrap", ref)
	})

	t.Run("invalid argument count", func(t *testing.T) {
		_, _, _, err := ParseChunkDictArgs("bootstrap:registry")
		require.EqualError(t, err, "invalid args")
	})

	t.Run("invalid format", func(t *testing.T) {
		_, _, _, err := ParseChunkDictArgs("blob:registry:docker.io/library/busybox:latest")
		require.ErrorContains(t, err, "invalid chunk dict format blob")
	})

	t.Run("invalid source", func(t *testing.T) {
		_, _, _, err := ParseChunkDictArgs("bootstrap:oss:docker.io/library/busybox:latest")
		require.ErrorContains(t, err, "invalid chunk dict source oss")
	})
}
