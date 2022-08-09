package manager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/containerd/nydus-snapshotter/config"
	nydusFS "github.com/containerd/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/containerd/nydus-snapshotter/pkg/process"
	"github.com/containerd/nydus-snapshotter/pkg/signature"
	"github.com/containerd/nydus-snapshotter/pkg/store"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/containers/nydus-storage-plugin/pkg/source"
)

const (
	remoteSnapshotLogKey = "remote-snapshot-prepared"
	prepareSucceeded     = "true"
	prepareFailed        = "false"

	defaultMaxConcurrency = 2
)

func NewLayerManager(ctx context.Context, rootDir string, hosts source.RegistryHosts, cfg *config.Config) (*LayerManager, error) {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return nil, err
	}

	db, err := store.NewDatabase(rootDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new database")
	}

	pm, err := process.NewManager(process.Opt{
		NydusdBinaryPath: cfg.NydusdBinaryPath,
		Database:         db,
		DaemonMode:       cfg.DaemonMode,
		CacheDir:         cfg.CacheDir,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to new process manager")
	}

	if err = os.Mkdir(filepath.Join(rootDir, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	opts := []nydusFS.NewFSOpt{
		nydusFS.WithProcessManager(pm),
		nydusFS.WithNydusdBinaryPath(cfg.NydusdBinaryPath, cfg.DaemonMode),
		nydusFS.WithMeta(rootDir),
		nydusFS.WithDaemonConfig(cfg.DaemonCfg),
		nydusFS.WithVPCRegistry(cfg.ConvertVpcRegistry),
		nydusFS.WithVerifier(verifier),
		nydusFS.WithDaemonMode(cfg.DaemonMode),
		nydusFS.WithLogLevel(cfg.LogLevel),
		nydusFS.WithLogDir(cfg.LogDir),
		nydusFS.WithLogToStdout(cfg.LogToStdout),
		nydusFS.WithNydusdThreadNum(cfg.NydusdThreadNum),
	}

	nydusFs, err := nydusFS.NewFileSystem(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize nydus filesystem")
	}

	refPool, err := newRefPool(ctx, rootDir, hosts)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("failed to setup resolver: %w", err)
	}
	return &LayerManager{
		refPool:    refPool,
		hosts:      hosts,
		refCounter: make(map[string]map[string]int),
		nydusFs:    nydusFs,
		rootDir:    rootDir,
	}, nil
}

// LayerManager manages layers of images and their resource lifetime.
type LayerManager struct {
	refPool *refPool
	hosts   source.RegistryHosts

	refCounter     map[string]map[string]int
	rootDir        string
	nydusMetaLayer sync.Map
	nydusFs        *nydusFS.Filesystem

	mu sync.Mutex
}

func (r *LayerManager) GetLayerInfo(ctx context.Context, refspec reference.Spec, dgst digest.Digest) (Layer, error) {
	manifest, config, err := r.refPool.loadRef(ctx, refspec)
	if err != nil {
		return Layer{}, fmt.Errorf("failed to get manifest and config: %w", err)
	}
	return genLayerInfo(dgst, manifest, config)
}

func (r *LayerManager) ResolverMetaLayer(ctx context.Context, refspec reference.Spec, rawRef string, digest digest.Digest) (*ocispec.Descriptor, error) {
	// get manifest from cache.
	manifest, _, err := r.refPool.loadRef(ctx, refspec)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest and config: %w", err)
	}
	var target ocispec.Descriptor
	var found bool
	for _, l := range manifest.Layers {
		if l.Digest == digest {
			l := l
			found = true
			target = l
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown digest %v for ref %q", target, refspec.String())
	}

	// Download nydus bootstrap layer and mount it.
	if _, ok := target.Annotations[label.NydusMetaLayer]; ok {
		target.Annotations[label.CRIImageRef] = refspec.String()
		target.Annotations[label.CRILayerDigest] = target.Digest.String()

		workdir := r.nydusFs.UpperPath(rawRef)
		if _, err := os.Stat(workdir); os.IsNotExist(err) {
			if err = os.MkdirAll(workdir, 0755); err != nil {
				log.G(ctx).Errorf("mkdir nydus snapshot dir failed: %+v", err)
				return nil, err
			}
		}

		// Download nydus bootstrap layer to disk.
		err = r.nydusFs.PrepareMetaLayer(ctx, storage.Snapshot{ID: rawRef}, target.Annotations)
		if err != nil && !strings.Contains(err.Error(), "file exists") {
			log.G(ctx).Errorf("download snapshot files failed: %+v", err)
			return nil, err
		}

		go func() {
			log.G(ctx).Debugf("nydus mount meta layer ref is %s digest is %s", refspec.String(), target.Digest.String())

			if _, ok := r.nydusMetaLayer.Load(refspec.String()); ok {
				log.G(ctx).Warnf("nydus duplicate mount meta layer ref is %s digest is %s", refspec.String(), target.Digest.String())
				return
			}

			err = r.nydusFs.Mount(ctx, rawRef, target.Annotations)
			if err != nil {
				log.G(ctx).Errorf("nydus mount failed: %+v", err)
				return
			}

			// Link nydusd mount dir to <mountpoint>/<ref>/<digest>/<diff>
			targetPath := fmt.Sprintf("%s/store/%s/%s/diff", r.rootDir, rawRef, target.Digest.String())
			mountPoint, err := r.nydusFs.MountPoint(rawRef)
			if err == nil {
				cmd := exec.Command("mount", "-o", "bind,ro", mountPoint, targetPath)
				err = cmd.Run()
				if err != nil {
					log.G(ctx).Errorf("mount bind file has error: %+v", err)
					return
				}
				r.nydusMetaLayer.Store(refspec.String(), targetPath)
			} else {
				log.G(ctx).Errorf("get mount point failed: %+v", err)
			}
		}()
	}
	return &target, nil
}

func (r *LayerManager) Release(ctx context.Context, refspec reference.Spec, dgst digest.Digest) (int, error) {
	r.refPool.release(refspec)
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refCounter == nil || r.refCounter[refspec.String()] == nil {
		return 0, fmt.Errorf("ref %q not tracked", refspec.String())
	} else if _, ok := r.refCounter[refspec.String()][dgst.String()]; !ok {
		return 0, fmt.Errorf("layer %q/%q not tracked", refspec.String(), dgst.String())
	}
	r.refCounter[refspec.String()][dgst.String()]--
	i := r.refCounter[refspec.String()][dgst.String()]
	if i <= 0 {
		if v, ok := r.nydusMetaLayer.Load(refspec.String()); ok {
			cmd := exec.Command("umount", v.(string))
			if err := cmd.Run(); err != nil {
				log.G(ctx).Errorf("umount bind nydus %v/%v failed: %+v", refspec, dgst, err)
				return 0, err
			}
			r.nydusMetaLayer.Delete(refspec.String())
		}

		// No reference to this layer. release it.
		delete(r.refCounter, dgst.String())
		if len(r.refCounter[refspec.String()]) == 0 {
			delete(r.refCounter, refspec.String())
		}
		log.G(ctx).WithField("refcounter", i).Infof("layer %v/%v is released due to no reference", refspec, dgst)
	}
	return i, nil
}

func (r *LayerManager) Use(refspec reference.Spec, dgst digest.Digest) int {
	r.refPool.use(refspec)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refCounter == nil {
		r.refCounter = make(map[string]map[string]int)
	}
	if r.refCounter[refspec.String()] == nil {
		r.refCounter[refspec.String()] = make(map[string]int)
	}
	if _, ok := r.refCounter[refspec.String()][dgst.String()]; !ok {
		r.refCounter[refspec.String()][dgst.String()] = 1
		return 1
	}
	r.refCounter[refspec.String()][dgst.String()]++
	return r.refCounter[refspec.String()][dgst.String()]
}

func (r *LayerManager) RefRoot() string {
	return r.refPool.root()
}

func colon2dash(s string) string {
	return strings.ReplaceAll(s, ":", "-")
}

// Layer represents the layer information. Format is compatible to the one required by
// "additional layer store" of github.com/containers/storage.
type Layer struct {
	CompressedDigest   digest.Digest `json:"compressed-diff-digest,omitempty"`
	CompressedSize     int64         `json:"compressed-size,omitempty"`
	UncompressedDigest digest.Digest `json:"diff-digest,omitempty"`
	UncompressedSize   int64         `json:"diff-size,omitempty"`
	CompressionType    int           `json:"compression,omitempty"`
	ReadOnly           bool          `json:"-"`
}

// Defined in https://github.com/containers/storage/blob/b64e13a1afdb0bfed25601090ce4bbbb1bc183fc/pkg/archive/archive.go#L108-L119
const gzipTypeMagicNum = 2

func genLayerInfo(dgst digest.Digest, manifest ocispec.Manifest, config ocispec.Image) (Layer, error) {
	if len(manifest.Layers) != len(config.RootFS.DiffIDs) {
		return Layer{}, fmt.Errorf(
			"len(manifest.Layers) != len(config.Rootfs): %d != %d",
			len(manifest.Layers), len(config.RootFS.DiffIDs))
	}
	var (
		layerIndex = -1
	)
	for i, l := range manifest.Layers {
		if l.Digest == dgst {
			layerIndex = i
		}
	}
	if layerIndex == -1 {
		return Layer{}, fmt.Errorf("layer %q not found in the manifest", dgst.String())
	}
	var uncompressedSize int64
	return Layer{
		CompressedDigest:   manifest.Layers[layerIndex].Digest,
		CompressedSize:     manifest.Layers[layerIndex].Size,
		UncompressedDigest: config.RootFS.DiffIDs[layerIndex],
		UncompressedSize:   uncompressedSize,
		CompressionType:    gzipTypeMagicNum,
		ReadOnly:           true,
	}, nil
}
