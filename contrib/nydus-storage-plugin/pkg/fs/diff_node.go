package fs

import (
	"context"
	"syscall"

	"github.com/containerd/containerd/log"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type diffNode struct {
	fusefs.Inode
	attr fuse.Attr
	fs   *fs
}

func (n *diffNode) Getattr(ctx context.Context, f fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	copyAttr(&out.Attr, &n.attr)
	return 0
}

func (n *diffNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	log.G(ctx).Infof("delete name %s", name)
	return syscall.ENOENT
}
