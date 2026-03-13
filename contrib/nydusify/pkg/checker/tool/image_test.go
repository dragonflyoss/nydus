package tool

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
)

func TestMkMounts(t *testing.T) {
	require.Nil(t, mkMounts(nil))

	single := mkMounts([]string{"/layers/0"})
	require.Len(t, single, 1)
	require.Equal(t, "/layers/0", single[0].Source)
	require.Equal(t, "bind", single[0].Type)
	require.Equal(t, []string{"ro", "rbind"}, single[0].Options)

	multiple := mkMounts([]string{"/layers/1", "/layers/0"})
	require.Len(t, multiple, 1)
	require.Equal(t, "overlay", multiple[0].Type)
	require.Equal(t, []string{"lowerdir=/layers/1:/layers/0"}, multiple[0].Options)
}

func TestCheckImageType(t *testing.T) {
	require.Equal(t, "unknown", CheckImageType(&parser.Parsed{}))
	require.Equal(t, "oci", CheckImageType(&parser.Parsed{OCIImage: &parser.Image{}}))
	require.Equal(t, "nydus", CheckImageType(&parser.Parsed{NydusImage: &parser.Image{}}))
}
