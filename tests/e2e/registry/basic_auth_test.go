package registry

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicAuth(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	credential := base64.StdEncoding.EncodeToString([]byte("nydus:secret"))
	proxy.RequireBasic(credential)

	tests := []struct {
		name   string
		auth   string
		expect func(t *testing.T, m *registryMount, err error)
	}{
		{
			name: "the configured credential answers the challenge",
			auth: credential,
			expect: func(t *testing.T, m *registryMount, err error) {
				require := require.New(t)
				require.NoError(err)
				require.Positive(proxy.Challenges())
				require.Zero(m.backendFailures(t, "ondemand", "origin"))
			},
		},
		{
			name: "a wrong credential fails the read",
			auth: base64.StdEncoding.EncodeToString([]byte("nydus:wrong")),
			expect: func(t *testing.T, m *registryMount, err error) {
				require := require.New(t)
				require.Error(err)
				require.Positive(proxy.Challenges())
				m.waitLogs(t, "401 Unauthorized")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := image.config("http://" + addr)
			config.Auth = tc.auth
			m := image.mount(t, config)
			tc.expect(t, m, m.read(t, image, "data/size/02097153"))
		})
	}
}
