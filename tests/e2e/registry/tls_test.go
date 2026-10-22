package registry

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestTLS(t *testing.T) {
	t.Parallel()
	image, proxy, _ := newRegistrySuite(t)

	// Serve the proxy over TLS with a certificate a private CA signed, which
	// nothing trusts by default.
	caCert, serverCert := newTestCA(t)
	server := httptest.NewUnstartedServer(proxy)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	tests := []struct {
		name   string
		tls    *mount.TLS
		expect func(t *testing.T, err error)
	}{
		{
			name: "an untrusted certificate fails the read",
			expect: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "skip_verify accepts it",
			tls:  &mount.TLS{SkipVerify: true},
			expect: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "ca_cert trusts it",
			tls:  &mount.TLS{CACert: caCert},
			expect: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := image.config(server.URL)
			config.HTTP.TLS = tc.tls
			m := image.mount(t, config)
			tc.expect(t, m.read(t, image, "data/size/02097153"))
		})
	}
}
