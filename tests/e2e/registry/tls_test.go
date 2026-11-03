package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestTLS(t *testing.T) {
	t.Parallel()
	image, proxy, _ := newRegistrySuite(t)

	caCert, serverCert := newTestCA(t)
	server := httptest.NewUnstartedServer(proxy)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	tests := []struct {
		name   string
		tls    *mount.TLSConfig
		expect func(t *testing.T, err error)
	}{
		{
			name: "UntrustedCertificateFails",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "SkipVerifyAccepts",
			tls:  &mount.TLSConfig{SkipVerify: true},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "CACertTrusts",
			tls:  &mount.TLSConfig{CACert: caCert},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
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

func newTestCA(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nydus e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	caPEM := filepath.Join(t.TempDir(), "ca.pem")
	if !assert.NoError(t, os.WriteFile(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)) {
		t.FailNow()
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	caParsed, err := x509.ParseCertificate(caDER)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caParsed, &serverKey.PublicKey, caKey)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return caPEM, tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
}
