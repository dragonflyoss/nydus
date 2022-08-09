// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/efc4166e93a22804b90e27c912eff7ecc0a12dfc/store/fs.go#L223-L303
package fs

import (
	"context"
	_ "crypto/sha256"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/opencontainers/go-digest"
)

// refNode is the node at <mountpoint>/<imageref>.
type refNode struct {
	fusefs.Inode
	fs     *fs
	attr   fuse.Attr
	ref    reference.Spec
	rawRef string
}

var _ = (fusefs.InodeEmbedder)((*refNode)(nil))
var _ = (fusefs.NodeLookuper)((*refNode)(nil))
var _ = (fusefs.NodeRmdirer)((*refNode)(nil))

func (n *refNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	// lookup on memory nodes
	log.L.WithContext(ctx).Debugf("ref node lookup name = %s", name)
	if child := n.GetChild(name); child != nil {
		switch tn := child.Operations().(type) {
		case *layerNode:
			copyAttr(&out.Attr, &tn.attr)
		default:
			log.G(ctx).Warn("rootnode.Lookup: uknown node type detected")
			return nil, syscall.EIO
		}
		out.Attr.Ino = child.StableAttr().Ino
		return child, 0
	}
	targetDigest, err := digest.Parse(name)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("invalid digest for %q", name)
		return nil, syscall.EINVAL
	}
	sAttr := defaultDirAttr(&out.Attr)
	child := &layerNode{
		fs:      n.fs,
		digest:  targetDigest,
		refNode: n,
	}
	copyAttr(&child.attr, &out.Attr)
	return n.fs.newInodeWithID(ctx, func(ino uint32) fusefs.InodeEmbedder {
		out.Attr.Ino = uint64(ino)
		child.attr.Ino = uint64(ino)
		sAttr.Ino = uint64(ino)
		return n.NewInode(ctx, child, sAttr)
	})
}

func (n *refNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	targetDigest, err := digest.Parse(name)
	if err != nil {
		log.G(ctx).WithError(err).Warnf("invalid digest for %q during release", name)
		return syscall.EINVAL
	}
	current, err := n.fs.layManager.Release(ctx, n.ref, targetDigest)
	if err != nil {
		log.G(ctx).WithError(err).Warnf("failed to release layer %v / %v", n.ref, targetDigest)
		return syscall.EIO
	}
	if current == 0 {
		n.fs.knownNodeMu.Lock()
		lh, ok := n.fs.knownNode[n.ref.String()][targetDigest.String()]
		if !ok {
			n.fs.knownNodeMu.Unlock()
			log.G(ctx).WithError(err).Warnf("node of layer %v/%v is not registered", n.ref, targetDigest)
			return syscall.EIO
		}
		lh.release()
		delete(n.fs.knownNode[n.ref.String()], targetDigest.String())
		if len(n.fs.knownNode[n.ref.String()]) == 0 {
			delete(n.fs.knownNode, n.ref.String())
		}
		n.fs.knownNodeMu.Unlock()
	}
	log.G(ctx).WithField("refcounter", current).Infof("layer %v/%v is marked as RELEASE", n.ref, targetDigest)
	return syscall.ENOENT
}
