package copier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFixBlobDigest(t *testing.T) {
	_, err := fixBlobDigests(
		"/home/imeoer/output/nydus_bootstrap", "/home/imeoer/nydus_bootstrap.fixed",
		map[string]string{
			"f0caa4821fb3f5cb53ca0563666b6029ab071b44caabca7073ebba880e8bda21": "f1caa4821fb3f5cb53ca0563666b6029ab071b44caabca7073ebba880e8bda21",
		})
	require.NoError(t, err)

	_, err = fixBlobDigests("/home/imeoer/nydus_bootstrap.fixed", "/home/imeoer/nydus_bootstrap.fixed",
		map[string]string{
			"7d0fc001a3376d250a02a7749f09f720a8d02911b85cd7c4723ceda97c217116": "710fc001a3376d250a02a7749f09f720a8d02911b85cd7c4723ceda97c217116",
		})
	require.NoError(t, err)

	_, err = fixBlobDigests("/home/imeoer/nydus_bootstrap.fixed", "/home/imeoer/nydus_bootstrap.fixed",
		map[string]string{
			"30af89d8656a224a257f0ce98f180090425263db245e4a6aee278c9fad39072c": "31af89d8656a224a257f0ce98f180090425263db245e4a6aee278c9fad39072c",
		})
	require.NoError(t, err)
}
