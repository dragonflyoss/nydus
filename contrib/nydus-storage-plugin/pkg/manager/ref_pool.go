// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/efc4166e93a22804b90e27c912eff7ecc0a12dfc/store/refs.go
package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containers/nydus-storage-plugin/pkg/cache"
	"github.com/containers/nydus-storage-plugin/pkg/source"
	"github.com/containers/nydus-storage-plugin/pkg/utils"
)

const (
	refCacheEntry            = 30
	defaultManifestCacheTime = 120 * time.Second
)

func newRefPool(ctx context.Context, root string, hosts source.RegistryHosts) (*refPool, error) {
	var poolroot = filepath.Join(root, "pool")
	if err := os.MkdirAll(poolroot, 0700); err != nil {
		return nil, err
	}
	p := &refPool{
		path:       poolroot,
		hosts:      hosts,
		refcounter: make(map[string]*releaser),
	}
	p.cache = cache.NewLRUCache(refCacheEntry)
	p.cache.OnEvicted = func(key string, value interface{}) {
		refspec := value.(reference.Spec)
		if err := os.RemoveAll(p.metadataDir(refspec)); err != nil {
			log.G(ctx).WithField("key", key).WithError(err).Warnf("failed to clean up ref")
			return
		}
		log.G(ctx).WithField("key", key).Debugf("cleaned up ref")
	}
	return p, nil
}

type refPool struct {
	path  string
	hosts source.RegistryHosts

	refcounter map[string]*releaser
	cache      *cache.LRUCache
	mu         sync.Mutex
}

type releaser struct {
	count   int
	release func()
}

func (p *refPool) loadRef(ctx context.Context, refspec reference.Spec) (manifest ocispec.Manifest, config ocispec.Image, err error) {
	manifest, config, err = p.readManifestAndConfig(refspec)
	if err == nil {
		log.G(ctx).Debugf("reusing manifest and config of %q", refspec.String())
		return
	}
	log.G(ctx).WithError(err).Debugf("fetching manifest and config of %q", refspec.String())
	manifest, config, err = p.fetchManifestAndConfig(ctx, refspec)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	if err := p.writeManifestAndConfig(refspec, manifest, config); err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	// Cache it so that next immediate call can acquire ref information from that dir.
	p.mu.Lock()
	_, done, _ := p.cache.Add(refspec.String(), refspec)
	p.mu.Unlock()
	go func() {
		// Release it after a reasonable amount of time.
		// If use() funcs are called for this reference, eviction of this won't be done until
		// all corresponding release() funcs are called.
		time.Sleep(defaultManifestCacheTime)
		done()
	}()
	return manifest, config, nil
}

func (p *refPool) use(refspec reference.Spec) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	r, ok := p.refcounter[refspec.String()]
	if !ok {
		_, done, _ := p.cache.Add(refspec.String(), refspec)
		p.refcounter[refspec.String()] = &releaser{
			count:   1,
			release: done,
		}
		return 1
	}
	r.count++
	return r.count
}

func (p *refPool) release(refspec reference.Spec) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	r, ok := p.refcounter[refspec.String()]
	if !ok {
		return 0, fmt.Errorf("ref %q not tracked", refspec.String())
	}
	r.count--
	if r.count <= 0 {
		delete(p.refcounter, refspec.String())
		r.release()
		return 0, nil
	}
	return r.count, nil
}

func (p *refPool) readManifestAndConfig(refspec reference.Spec) (manifest ocispec.Manifest, config ocispec.Image, _ error) {
	mPath, cPath := p.manifestFile(refspec), p.configFile(refspec)
	mf, err := os.Open(mPath)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	defer mf.Close()
	if err := json.NewDecoder(mf).Decode(&manifest); err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	cf, err := os.Open(cPath)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	defer cf.Close()
	if err := json.NewDecoder(cf).Decode(&config); err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	return manifest, config, nil
}

func (p *refPool) writeManifestAndConfig(refspec reference.Spec, manifest ocispec.Manifest, config ocispec.Image) error {
	mPath, cPath := p.manifestFile(refspec), p.configFile(refspec)
	log.G(context.TODO()).Infof("mpath = %s, cpath = %s", mPath, cPath)
	if err := os.MkdirAll(filepath.Dir(mPath), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cPath), 0700); err != nil {
		return err
	}
	mf, err := os.Create(mPath)
	if err != nil {
		return err
	}
	defer mf.Close()
	if err := json.NewEncoder(mf).Encode(&manifest); err != nil {
		return err
	}
	cf, err := os.Create(cPath)
	if err != nil {
		return err
	}
	defer cf.Close()
	return json.NewEncoder(cf).Encode(&config)
}

func (p *refPool) fetchManifestAndConfig(ctx context.Context, refspec reference.Spec) (ocispec.Manifest, ocispec.Image, error) {
	// temporary resolver. should only be used for resolving `refpec`.
	resolver := docker.NewResolver(docker.ResolverOptions{
		Hosts: func(host string) ([]docker.RegistryHost, error) {
			if host != refspec.Hostname() {
				return nil, fmt.Errorf("unexpected host %q for image ref %q", host, refspec.String())
			}
			return p.hosts(refspec)
		},
	})

	_, img, err := resolver.Resolve(ctx, refspec.String())
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	fetcher, err := resolver.Fetcher(ctx, refspec.String())
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	plt := platforms.DefaultSpec()
	manifest, err := fetchManifestPlatform(ctx, fetcher, img, plt)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	r, err := fetcher.Fetch(ctx, manifest.Config)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}
	defer r.Close()
	var config ocispec.Image
	if err := json.NewDecoder(r).Decode(&config); err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, err
	}

	return manifest, config, nil
}

func (p *refPool) root() string {
	return p.path
}

func (p *refPool) metadataDir(refspec reference.Spec) string {
	return filepath.Join(p.path, "metadata--"+colon2dash(digest.FromString(refspec.String()).String()))
}

func (p *refPool) manifestFile(refspec reference.Spec) string {
	return filepath.Join(p.metadataDir(refspec), "manifest")
}

func (p *refPool) configFile(refspec reference.Spec) string {
	return filepath.Join(p.metadataDir(refspec), "config")
}

func fetchManifestPlatform(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor, platform ocispec.Platform) (ocispec.Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	r, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return ocispec.Manifest{}, err
	}
	defer r.Close()

	var manifest ocispec.Manifest
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		p, err := io.ReadAll(r)
		if err != nil {
			return ocispec.Manifest{}, err
		}
		if err := utils.ValidateMediaType(p, desc.MediaType); err != nil {
			return ocispec.Manifest{}, err
		}
		if err := json.Unmarshal(p, &manifest); err != nil {
			return ocispec.Manifest{}, err
		}
		return manifest, nil
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		var index ocispec.Index
		p, err := io.ReadAll(r)
		if err != nil {
			return ocispec.Manifest{}, err
		}
		if err := utils.ValidateMediaType(p, desc.MediaType); err != nil {
			return ocispec.Manifest{}, err
		}
		if err = json.Unmarshal(p, &index); err != nil {
			return ocispec.Manifest{}, err
		}
		var target ocispec.Descriptor
		found := false
		for _, m := range index.Manifests {
			p := platforms.DefaultSpec()
			if m.Platform != nil {
				p = *m.Platform
			}
			if !platforms.NewMatcher(platform).Match(p) {
				continue
			}
			target = m
			found = true
			break
		}
		if !found {
			return ocispec.Manifest{}, fmt.Errorf("no manifest found for platform")
		}
		return fetchManifestPlatform(ctx, fetcher, target, platform)
	}
	return ocispec.Manifest{}, fmt.Errorf("unknown mediatype %q", desc.MediaType)
}
