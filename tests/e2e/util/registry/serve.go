package registry

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

// Served is an image whose blobs a registry serves under one repository.
type Served struct {
	Image    fixture.Image
	Registry *Registry
	Repo     string
}

// Serve starts a registry and pushes the image's blobs to repo.
func Serve(t testing.TB, img fixture.Image, repo string) *Served {
	t.Helper()
	reg := Start(t)
	reg.PushBlobs(t, repo, img.Blobs)

	return &Served{Image: img, Registry: reg, Repo: repo}
}

// backend is the registry backend config pointing at the served repository.
func (s *Served) backend() mount.RegistryConfig {
	return mount.RegistryConfig{Addr: s.Registry.URL, Repository: s.Repo}
}

// Mount serves the image through a from the registry; opts.Config, if
// given, adjusts the generated config after the backend is set.
func (s *Served) Mount(t testing.TB, a mount.Adapter, opts mount.Options) *mount.Mounted {
	t.Helper()
	edit := opts.Config

	opts.Config = func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(s.backend())

		if edit != nil {
			edit(c)
		}
	}

	return mount.Mount(t, a, s.Image, opts)
}

// BlobGets counts the blob GETs the registry has served.
func (s *Served) BlobGets() int { return s.Registry.Faults.BlobGets() }
