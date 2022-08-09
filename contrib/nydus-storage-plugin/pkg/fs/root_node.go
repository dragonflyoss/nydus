// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/efc4166e93a22804b90e27c912eff7ecc0a12dfc/store/fs.go#L159-L221
package fs

import (
	"context"
	"encoding/base64"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// rootnode is the mountpoint node of nydus-store.
type rootNode struct {
	fusefs.Inode
	fs *fs
}

var _ = (fusefs.InodeEmbedder)((*rootNode)(nil))

var _ = (fusefs.NodeLookuper)((*rootNode)(nil))

// Lookup loads manifest and config of specified name (image reference)
// and returns refnode of the specified name
func (n *rootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	log.L.WithContext(ctx).Debugf("root node lookup name = %s", name)
	if child := n.GetChild(name); child != nil {
		switch tn := child.Operations().(type) {
		case *fusefs.MemSymlink:
			copyAttr(&out.Attr, &tn.Attr)
		case *refNode:
			copyAttr(&out.Attr, &tn.attr)
		default:
			log.L.WithContext(ctx).Warn("rootNode.Lookup: unknown node type detected")
			return nil, syscall.EIO
		}
		out.Attr.Ino = child.StableAttr().Ino
		return child, 0
	}

	switch name {
	case poolLink:
		// filesystem cache.
		sAttr := defaultLinkAttr(&out.Attr)
		cn := &fusefs.MemSymlink{Data: []byte(n.fs.layManager.RefRoot())}
		copyAttr(&cn.Attr, &out.Attr)
		return n.fs.newInodeWithID(ctx, func(ino uint32) fusefs.InodeEmbedder {
			out.Attr.Ino = uint64(ino)
			cn.Attr.Ino = uint64(ino)
			sAttr.Ino = uint64(ino)
			return n.NewInode(ctx, cn, sAttr)
		})
	}

	refBytes, err := base64.StdEncoding.DecodeString(name)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("failed to decode ref base64 %q", name)
		return nil, syscall.EINVAL
	}
	ref := string(refBytes)
	var refSpec reference.Spec
	refSpec, err = reference.Parse(ref)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("invalid reference %q for %q", ref, name)
		return nil, syscall.EINVAL
	}
	sAttr := defaultDirAttr(&out.Attr)
	child := &refNode{
		fs:     n.fs,
		ref:    refSpec,
		rawRef: name,
	}
	copyAttr(&child.attr, &out.Attr)
	return n.fs.newInodeWithID(ctx, func(ino uint32) fusefs.InodeEmbedder {
		out.Attr.Ino = uint64(ino)
		child.attr.Ino = uint64(ino)
		sAttr.Ino = uint64(ino)
		return n.NewInode(ctx, child, sAttr)
	})
}
