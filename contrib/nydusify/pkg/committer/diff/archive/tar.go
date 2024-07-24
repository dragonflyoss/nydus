/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package archive

import (
	"archive/tar"
	"context"

	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/continuity/fs"
)

var bufPool = &sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 32*1024)
		return &buffer
	},
}

const (
	// whiteoutPrefix prefix means file is a whiteout. If this is followed by a
	// filename this means that file has been removed from the base layer.
	// See https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
	whiteoutPrefix = ".wh."

	paxSchilyXattr = "SCHILY.xattr."
)

// ChangeWriter provides tar stream from filesystem change information.
// The provided tar stream is styled as an OCI layer. Change information
// (add/modify/delete/unmodified) for each file needs to be passed to this
// writer through HandleChange method.
//
// This should be used combining with continuity's diff computing functionality
// (e.g. `fs.Change` of github.com/containerd/continuity/fs).
//
// See also https://github.com/opencontainers/image-spec/blob/main/layer.md for details
// about OCI layers
type ChangeWriter struct {
	tw                *tar.Writer
	source            string
	modTimeUpperBound *time.Time
	whiteoutT         time.Time
	inodeSrc          map[uint64]string
	inodeRefs         map[uint64][]string
	addedDirs         map[string]struct{}
}

// ChangeWriterOpt can be specified in NewChangeWriter.
type ChangeWriterOpt func(cw *ChangeWriter)

// NewChangeWriter returns ChangeWriter that writes tar stream of the source directory
// to the provided writer. Change information (add/modify/delete/unmodified) for each
// file needs to be passed through HandleChange method.
func NewChangeWriter(w io.Writer, source string, opts ...ChangeWriterOpt) *ChangeWriter {
	cw := &ChangeWriter{
		tw:        tar.NewWriter(w),
		source:    source,
		whiteoutT: time.Now(), // can be overridden with WithWhiteoutTime(time.Time) ChangeWriterOpt .
		inodeSrc:  map[uint64]string{},
		inodeRefs: map[uint64][]string{},
		addedDirs: map[string]struct{}{},
	}
	for _, o := range opts {
		o(cw)
	}
	return cw
}

// HandleChange receives filesystem change information and reflect that information to
// the result tar stream. This function implements `fs.ChangeFunc` of continuity
// (github.com/containerd/continuity/fs) and should be used with that package.
func (cw *ChangeWriter) HandleChange(k fs.ChangeKind, p string, f os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if k == fs.ChangeKindDelete {
		whiteOutDir := filepath.Dir(p)
		whiteOutBase := filepath.Base(p)
		whiteOut := filepath.Join(whiteOutDir, whiteoutPrefix+whiteOutBase)
		hdr := &tar.Header{
			Typeflag:   tar.TypeReg,
			Name:       whiteOut[1:],
			Size:       0,
			ModTime:    cw.whiteoutT,
			AccessTime: cw.whiteoutT,
			ChangeTime: cw.whiteoutT,
		}
		if err := cw.includeParents(hdr); err != nil {
			return err
		}
		if err := cw.tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write whiteout header: %w", err)
		}
	} else {
		var (
			link   string
			err    error
			source = filepath.Join(cw.source, p)
		)

		switch {
		case f.Mode()&os.ModeSocket != 0:
			return nil // ignore sockets
		case f.Mode()&os.ModeSymlink != 0:
			if link, err = os.Readlink(source); err != nil {
				return err
			}
		}

		hdr, err := tar.FileInfoHeader(f, link)
		if err != nil {
			return err
		}

		hdr.Mode = int64(chmodTarEntry(os.FileMode(hdr.Mode)))

		// truncate timestamp for compatibility. without PAX stdlib rounds timestamps instead
		hdr.Format = tar.FormatPAX
		if cw.modTimeUpperBound != nil && hdr.ModTime.After(*cw.modTimeUpperBound) {
			hdr.ModTime = *cw.modTimeUpperBound
		}
		hdr.ModTime = hdr.ModTime.Truncate(time.Second)
		hdr.AccessTime = time.Time{}
		hdr.ChangeTime = time.Time{}

		name := p
		if strings.HasPrefix(name, string(filepath.Separator)) {
			name, err = filepath.Rel(string(filepath.Separator), name)
			if err != nil {
				return fmt.Errorf("failed to make path relative: %w", err)
			}
		}
		// Canonicalize to POSIX-style paths using forward slashes. Directory
		// entries must end with a slash.
		name = filepath.ToSlash(name)
		if f.IsDir() && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		hdr.Name = name

		if err := setHeaderForSpecialDevice(hdr, name, f); err != nil {
			return fmt.Errorf("failed to set device headers: %w", err)
		}

		// additionalLinks stores file names which must be linked to
		// this file when this file is added
		var additionalLinks []string
		inode, isHardlink := fs.GetLinkInfo(f)
		if isHardlink {
			// If the inode has a source, always link to it
			if source, ok := cw.inodeSrc[inode]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = source
				hdr.Size = 0
			} else {
				if k == fs.ChangeKindUnmodified {
					cw.inodeRefs[inode] = append(cw.inodeRefs[inode], name)
					return nil
				}
				cw.inodeSrc[inode] = name
				additionalLinks = cw.inodeRefs[inode]
				delete(cw.inodeRefs, inode)
			}
		} else if k == fs.ChangeKindUnmodified {
			// Nothing to write to diff
			return nil
		}

		if capability, err := getxattr(source, "security.capability"); err != nil {
			return fmt.Errorf("failed to get capabilities xattr: %w", err)
		} else if len(capability) > 0 {
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords[paxSchilyXattr+"security.capability"] = string(capability)
		}

		if err := cw.includeParents(hdr); err != nil {
			return err
		}
		if err := cw.tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write file header: %w", err)
		}

		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			file, err := open(source)
			if err != nil {
				return fmt.Errorf("failed to open path: %v: %w", source, err)
			}
			defer file.Close()

			// HACK (imeoer): display file path in error message.
			n, err := copyBuffered(context.TODO(), cw.tw, file)
			if err != nil {
				return fmt.Errorf("failed to copy file %s: %w", p, err)
			}
			if n != hdr.Size {
				return fmt.Errorf("short write copying file: %s", p)
			}
		}

		if additionalLinks != nil {
			source = hdr.Name
			for _, extra := range additionalLinks {
				hdr.Name = extra
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = source
				hdr.Size = 0

				if err := cw.includeParents(hdr); err != nil {
					return err
				}
				if err := cw.tw.WriteHeader(hdr); err != nil {
					return fmt.Errorf("failed to write file header: %w", err)
				}
			}
		}
	}
	return nil
}

// Close closes this writer.
func (cw *ChangeWriter) Close() error {
	if err := cw.tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}
	return nil
}

func (cw *ChangeWriter) includeParents(hdr *tar.Header) error {
	if cw.addedDirs == nil {
		return nil
	}
	name := strings.TrimRight(hdr.Name, "/")
	fname := filepath.Join(cw.source, name)
	parent := filepath.Dir(name)
	pname := filepath.Join(cw.source, parent)

	// Do not include root directory as parent
	if fname != cw.source && pname != cw.source {
		_, ok := cw.addedDirs[parent]
		if !ok {
			cw.addedDirs[parent] = struct{}{}
			fi, err := os.Stat(pname)
			if err != nil {
				return err
			}
			if err := cw.HandleChange(fs.ChangeKindModify, parent, fi, nil); err != nil {
				return err
			}
		}
	}
	if hdr.Typeflag == tar.TypeDir {
		cw.addedDirs[name] = struct{}{}
	}
	return nil
}

func copyBuffered(ctx context.Context, dst io.Writer, src io.Reader) (written int64, err error) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		default:
		}

		nr, er := src.Read(*buf)
		if nr > 0 {
			nw, ew := dst.Write((*buf)[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err

}
