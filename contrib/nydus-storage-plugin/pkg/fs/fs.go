// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/efc4166e93a22804b90e27c912eff7ecc0a12dfc/store/fs.go#L43-#L157
package fs

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containers/nydus-storage-plugin/pkg/manager"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

const (
	defaultLinkMode = syscall.S_IFLNK | 0400 // -r--------
	defaultDirMode  = syscall.S_IFDIR | 0500 // dr-x------
	defaultFileMode = 0400                   // -r--------
	layerFileMode   = 0400                   // -r--------
	blockSize       = 4096

	poolLink      = "pool"
	layerLink     = "diff"
	blobLink      = "blob"
	layerInfoLink = "info"
	layerUseFile  = "use"

	fusermountBin = "fusermount"
)

type releasable interface {
	releasable() bool
}

type fs struct {
	// nodeMap manages inode numbers for nodes other than nodes in layers
	// (i.e. nodes other than ones inside `diff` directories).
	// - inode number = [ 0 ][ uint32 ID ]
	nodeMap *idMap
	// layerMap manages upper bits of inode numbers for nodes inside layers.
	// - inode number = [ uint32 layer ID ][ uint32 number (unique inside `diff` directory) ]
	// inodes numbers of noeds inside each `diff` directory are prefixed by an unique uint32
	// so that they don't conflict with nodes outside `diff` directories.
	layerMap *idMap

	knownNode   map[string]map[string]*layerReleasable
	knownNodeMu sync.Mutex
	layManager  *manager.LayerManager
}

type layerReleasable struct {
	n        fusefs.InodeEmbedder
	released bool
	mu       sync.Mutex
}

func (lh *layerReleasable) releasable() bool {
	lh.mu.Lock()
	released := lh.released
	lh.mu.Unlock()
	return released && isForgotten(lh.n.EmbeddedInode())
}

func (lh *layerReleasable) release() {
	lh.mu.Lock()
	lh.released = true
	lh.mu.Unlock()
}

type inoReleasable struct {
	n fusefs.InodeEmbedder
}

func (r *inoReleasable) releasable() bool {
	return r.n.EmbeddedInode().Forgotten()
}

func Mount(ctx context.Context, mountPoint string, rootDir string, debug bool, layManager *manager.LayerManager) error {
	seconds := time.Second
	rawFS := fusefs.NewNodeFS(&rootNode{
		fs: &fs{
			nodeMap:    new(idMap),
			layerMap:   new(idMap),
			layManager: layManager,
		},
	}, &fusefs.Options{
		AttrTimeout:     &seconds,
		EntryTimeout:    &seconds,
		NullPermissions: true,
	})
	mountOpts := &fuse.MountOptions{
		AllowOther: true, // allow users other than root&mounter to access fs
		FsName:     "nydusstore",
		Debug:      debug,
	}
	if _, err := exec.LookPath(fusermountBin); err == nil {
		mountOpts.Options = []string{"suid"} // option for fusermount; allow setuid inside container
	} else {
		log.L.WithError(err).Debugf("%s not installed; trying direct mount", fusermountBin)
		mountOpts.DirectMount = true
	}
	server, err := fuse.NewServer(rawFS, mountPoint, mountOpts)
	if err != nil {
		return err
	}
	go server.Serve()
	return server.WaitMount()
}

func (fs *fs) newInodeWithID(ctx context.Context, p func(uint32) fusefs.InodeEmbedder) (*fusefs.Inode, syscall.Errno) {
	var ino fusefs.InodeEmbedder
	if err := fs.nodeMap.add(func(id uint32) (releasable, error) {
		ino = p(id)
		return &inoReleasable{ino}, nil
	}); err != nil || ino == nil {
		log.L.WithContext(ctx).WithError(err).Debug("cannot generate ID")
		return nil, syscall.EIO
	}
	return ino.EmbeddedInode(), 0
}
