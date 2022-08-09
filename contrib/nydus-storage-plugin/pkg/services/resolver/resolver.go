// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/974b0d5c2c3c4364d670313cde9370c83089985f/service/resolver/registry.go
package resolver

import (
	"time"

	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes/docker"
	rhttp "github.com/hashicorp/go-retryablehttp"

	"github.com/containers/nydus-storage-plugin/pkg/source"
)

const defaultRequestTimeoutSec = 30

// Config is config for resolving registries.
type Config struct {
	Host map[string]HostConfig `toml:"host"`
}

type HostConfig struct {
	Mirrors []MirrorConfig `toml:"mirrors"`
}

type MirrorConfig struct {

	// Host is the hostname of the host.
	Host string `toml:"host"`

	// Insecure is true means use http scheme instead of https.
	Insecure bool `toml:"insecure"`

	// RequestTimeoutSec is timeout seconds of each request to the registry.
	// RequestTimeoutSec == 0 indicates the default timeout (defaultRequestTimeoutSec).
	// RequestTimeoutSec < 0 indicates no timeout.
	RequestTimeoutSec int `toml:"request_timeout_sec"`
}

type Credential func(string, reference.Spec) (string, string, error)

// RegistryHostsFromConfig creates RegistryHosts (a set of registry configuration) from Config.
func RegistryHostsFromConfig(credsFuncs ...Credential) source.RegistryHosts {
	return func(ref reference.Spec) (hosts []docker.RegistryHost, _ error) {
		host := ref.Hostname()
		for _, h := range []MirrorConfig{
			{Host: host},
		} {
			client := rhttp.NewClient()
			client.Logger = nil // disable logging every request
			tr := client.StandardClient()
			if h.RequestTimeoutSec >= 0 {
				if h.RequestTimeoutSec == 0 {
					tr.Timeout = defaultRequestTimeoutSec * time.Second
				} else {
					tr.Timeout = time.Duration(h.RequestTimeoutSec) * time.Second
				}
			} // h.RequestTimeoutSec < 0 means "no timeout"
			config := docker.RegistryHost{
				Client:       tr,
				Host:         h.Host,
				Scheme:       "https",
				Path:         "/v2",
				Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve,
				Authorizer: docker.NewDockerAuthorizer(
					docker.WithAuthClient(tr),
					docker.WithAuthCreds(multiCredsFuncs(ref, credsFuncs...))),
			}
			if localhost, _ := docker.MatchLocalhost(config.Host); localhost || h.Insecure {
				config.Scheme = "http"
			}
			if config.Host == "docker.io" {
				config.Host = "registry-1.docker.io"
			}
			hosts = append(hosts, config)
		}
		return
	}
}

func multiCredsFuncs(ref reference.Spec, credsFuncs ...Credential) func(string) (string, string, error) {
	return func(host string) (string, string, error) {
		for _, f := range credsFuncs {
			if username, secret, err := f(host, ref); err != nil {
				return "", "", err
			} else if !(username == "" && secret == "") {
				return username, secret, nil
			}
		}
		return "", "", nil
	}
}
