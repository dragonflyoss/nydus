package fs

import (
	"context"
	"syscall"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// blobNode is a regular file node that contains raw blob data
type blobNode struct {
	fusefs.Inode
	attr fuse.Attr
	l    *ocispec.Descriptor
}

var _ = (fusefs.InodeEmbedder)((*blobNode)(nil))

var _ = (fusefs.NodeOpener)((*blobNode)(nil))

func (n *blobNode) Open(ctx context.Context, flags uint32) (fh fusefs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return &blobFile{}, 0, 0
}
