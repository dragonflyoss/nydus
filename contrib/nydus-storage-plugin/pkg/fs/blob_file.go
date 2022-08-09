package fs

import (
	"context"
	"syscall"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// blob file is the file handle of blob contents.
type blobFile struct {
}

var _ = (fusefs.FileReader)((*blobFile)(nil))

func (f *blobFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	//s, err := f.l.ReadAt(dest, off,
	//	remote.WithContext(ctx),              // Make cancellable
	//	remote.WithCacheOpts(cache.Direct()), // Do not pollute mem cache
	//)
	//if err != nil && err != io.EOF {
	//	return nil, syscall.EIO
	//}
	//return fuse.ReadResultData(dest[:s]), 0
	return nil, syscall.EIO
}

var _ = (fusefs.FileGetattrer)((*blobFile)(nil))

func (f *blobFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	//layerToAttr(f.l, &out.Attr)
	return 0
}
