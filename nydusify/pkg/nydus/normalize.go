/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"math"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// typeGNUDumpDir is GNU's incremental directory entry, which Go reads but
// does not name.
const typeGNUDumpDir = 'D'

// maxLinksWalked bounds symlink resolution as continuity's fs.RootPath does.
const maxLinksWalked = 255

// Linux XATTR_NAME_MAX and XATTR_SIZE_MAX.
const (
	xattrNameMax = 255
	xattrSizeMax = 65536
)

// Apply bounds member times to what os.Chtimes can set.
var (
	minApplyTime = time.Unix(0, 0)
	maxApplyTime = time.Unix(0, math.MaxInt64)
)

// normalizeTar re-encodes the layer tar read from r as a canonical stream on
// w describing the tree containerd's archive.Apply builds from it: Go's
// archive/tar parses every header format and sparse encoding, member paths
// are resolved within the root through the symlinks earlier members made,
// and each member is written again as a plain PAX header. Archives Go or
// Apply reject are rejected, and OCI whiteouts pass through as plain files.
func normalizeTar(w io.Writer, r io.Reader) error {
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	root := newTarDir()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read layer tar")
		}
		out, err := root.apply(hdr)
		if err != nil {
			return errors.Wrapf(err, "layer tar member %q", hdr.Name)
		}
		if out == nil {
			continue
		}
		if err := tw.WriteHeader(out); err != nil {
			return errors.Wrapf(err, "write layer tar member %q", out.Name)
		}
		if out.Typeflag == tar.TypeReg {
			if _, err := io.Copy(tw, tr); err != nil {
				return errors.Wrapf(err, "copy layer tar member %q", hdr.Name)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return errors.Wrap(err, "finish layer tar")
	}
	// Whatever follows the end-of-archive marker is ignored, but must be
	// consumed so the writer feeding r is not blocked.
	_, err := io.Copy(io.Discard, r)
	return err
}

// tarNode is what later members observe of an applied inode. Hard links
// share one node.
type tarNode struct {
	typeflag byte
	linkname string
	xattrs   map[string]string
	children map[string]*tarNode
}

func newTarDir() *tarNode {
	return &tarNode{typeflag: tar.TypeDir, children: map[string]*tarNode{}}
}

// apply records hdr the way archive.Apply lands it and returns the member to
// emit, or nil for one Apply ignores.
func (root *tarNode) apply(hdr *tar.Header) (*tar.Header, error) {
	typeflag := hdr.Typeflag
	switch typeflag {
	case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
	case tar.TypeRegA, tar.TypeCont, tar.TypeGNUSparse:
		typeflag = tar.TypeReg
	case typeGNUDumpDir:
		typeflag = tar.TypeDir
	case tar.TypeXGlobalHeader:
		return nil, nil
	default:
		return nil, errors.Errorf("unsupported type %q", typeflag)
	}

	parentPath, base := path.Split(path.Clean(hdr.Name))
	parentPath, err := root.rootPath(parentPath)
	if err != nil {
		return nil, err
	}
	target := path.Join(parentPath, path.Join("/", base))
	if target == "/" {
		return nil, nil
	}
	for _, comp := range strings.Split(target[1:], "/") {
		if len(comp) > unix.NAME_MAX {
			return nil, errors.New("name component too long")
		}
	}
	parent, err := root.mkparent(parentPath)
	if err != nil {
		return nil, err
	}
	if err := validateWhiteout(target); err != nil {
		return nil, err
	}

	name := path.Base(target)
	existing := parent.children[name]
	if existing != nil && (existing.typeflag != tar.TypeDir || typeflag != tar.TypeDir) {
		delete(parent.children, name)
		existing = nil
	}

	out := &tar.Header{
		Typeflag: typeflag,
		Name:     target[1:],
		Mode:     hdr.Mode & 0o7777,
		Uid:      applyID(hdr.Uid),
		Gid:      applyID(hdr.Gid),
		ModTime:  boundTime(hdr.ModTime),
	}
	var node *tarNode
	switch typeflag {
	case tar.TypeDir:
		node = existing
		if node == nil {
			node = newTarDir()
		}
		out.Name += "/"
	case tar.TypeReg:
		node = &tarNode{typeflag: typeflag}
		out.Size = hdr.Size
	case tar.TypeChar, tar.TypeBlock:
		node = &tarNode{typeflag: typeflag}
		out.Devmajor, out.Devminor = mknodDev(hdr.Devmajor, hdr.Devminor)
	case tar.TypeFifo:
		node = &tarNode{typeflag: typeflag}
	case tar.TypeSymlink:
		if hdr.Linkname == "" {
			return nil, errors.New("empty symlink target")
		}
		node = &tarNode{typeflag: typeflag, linkname: hdr.Linkname}
		out.Linkname = hdr.Linkname
		out.Mode = 0o777
	case tar.TypeLink:
		// Like hardlinkRootPath: the link's parent is resolved, its last
		// component is not.
		linkParent, linkBase := path.Split(hdr.Linkname)
		linkParent, err := root.rootPath(linkParent)
		if err != nil {
			return nil, err
		}
		linkTarget := path.Join(linkParent, linkBase)
		node = root.lookup(linkTarget)
		if node == nil {
			return nil, errors.Errorf("hard link target %q not found", hdr.Linkname)
		}
		if node.typeflag == tar.TypeDir {
			return nil, errors.Errorf("hard link target %q is a directory", hdr.Linkname)
		}
		out.Linkname = linkTarget[1:]
	}

	xattrs, err := applyXattrs(node.typeflag, hdr.PAXRecords)
	if err != nil {
		return nil, err
	}
	if typeflag == tar.TypeDir && node.xattrs != nil {
		// Apply sets xattrs on the directory it merges into.
		merged := maps.Clone(node.xattrs)
		maps.Copy(merged, xattrs)
		xattrs = merged
	}
	if typeflag == tar.TypeDir {
		node.xattrs = xattrs
	}
	for key, value := range xattrs {
		if out.PAXRecords == nil {
			out.PAXRecords = map[string]string{}
		}
		if strings.Contains(key, "\n") || strings.Contains(value, "\n") {
			// nydus build splits PAX records at newlines; libarchive's
			// encoding carries none.
			out.PAXRecords["LIBARCHIVE.xattr."+percentEncode(key)] = base64.StdEncoding.EncodeToString([]byte(value))
		} else {
			out.PAXRecords["SCHILY.xattr."+key] = value
		}
	}
	out.Format = tar.FormatPAX
	if !utf8.ValidString(out.Name) || !utf8.ValidString(out.Linkname) ||
		strings.Contains(out.Name, "\n") || strings.Contains(out.Linkname, "\n") {
		// PAX paths must be UTF-8 and, for nydus build, free of newlines.
		out.Format = tar.FormatGNU
	}
	parent.children[name] = node
	return out, nil
}

// lookup finds p like lstat(2): symlinks in leading components are
// followed within the root, the last component is not.
func (root *tarNode) lookup(p string) *tarNode {
	return root.lookupDepth(p, 0)
}

func (root *tarNode) lookupDepth(p string, depth int) *tarNode {
	if depth > maxLinksWalked {
		return nil
	}
	comps := strings.Split(strings.TrimPrefix(path.Clean("/"+p), "/"), "/")
	cur := root
	for i, comp := range comps {
		if comp == "" {
			return cur
		}
		node := cur.children[comp]
		if node == nil || i == len(comps)-1 {
			return node
		}
		switch node.typeflag {
		case tar.TypeDir:
			cur = node
		case tar.TypeSymlink:
			link := node.linkname
			if !path.IsAbs(link) {
				link = path.Join("/", path.Join(comps[:i]...), link)
			}
			return root.lookupDepth(path.Join(append([]string{link}, comps[i+1:]...)...), depth+1)
		default:
			return nil
		}
	}
	return cur
}

// rootPath resolves p within the root through the symlinks recorded so far,
// following continuity's fs.RootPath step for step.
func (root *tarNode) rootPath(p string) (string, error) {
	if p == "" {
		return "/", nil
	}
	var walked int
	for {
		before := walked
		next, err := root.walkLinks(p, &walked)
		if err != nil {
			return "", err
		}
		p = next
		if before == walked {
			next = path.Join("/", next)
			if p == next {
				return next, nil
			}
			p = next
		}
	}
}

func (root *tarNode) walkLink(p string, walked *int) (string, bool, error) {
	if *walked > maxLinksWalked {
		return "", false, errors.New("too many symlinks")
	}
	p = path.Join("/", p)
	if p == "/" {
		return p, false, nil
	}
	node := root.lookup(p)
	if node == nil || node.typeflag != tar.TypeSymlink {
		return p, false, nil
	}
	*walked++
	return node.linkname, true, nil
}

func (root *tarNode) walkLinks(p string, walked *int) (string, error) {
	switch dir, file := path.Split(p); {
	case dir == "":
		next, _, err := root.walkLink(file, walked)
		return next, err
	case file == "":
		if dir == "/" {
			return dir, nil
		}
		return root.walkLinks(dir[:len(dir)-1], walked)
	default:
		dir, err := root.walkLinks(dir, walked)
		if err != nil {
			return "", err
		}
		next, isLink, err := root.walkLink(path.Join(dir, file), walked)
		if err != nil || !isLink || path.IsAbs(next) {
			return next, err
		}
		return path.Join(dir, next), nil
	}
}

// mkparent returns the directory at the resolved path p, recording missing
// ones as the implicit directories Apply creates.
func (root *tarNode) mkparent(p string) (*tarNode, error) {
	cur := root
	for _, comp := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if comp == "" {
			continue
		}
		node := cur.children[comp]
		if node == nil {
			node = newTarDir()
			cur.children[comp] = node
		} else if node.typeflag != tar.TypeDir {
			return nil, errors.Errorf("parent %q is not a directory", p)
		}
		cur = node
	}
	return cur, nil
}

// validateWhiteout rejects whiteout names that would remove something
// outside their own directory, as Apply does.
func validateWhiteout(p string) error {
	base := path.Base(p)
	if base == ".wh..wh..opq" || !strings.HasPrefix(base, ".wh.") {
		return nil
	}
	dir := path.Dir(p)
	original := path.Join(dir, strings.TrimPrefix(base, ".wh."))
	if original == dir || !strings.HasPrefix(original, strings.TrimSuffix(dir, "/")+"/") {
		return errors.Errorf("invalid whiteout name %q", base)
	}
	return nil
}

// applyXattrs keeps the xattrs Apply sets on an inode of type typeflag: it
// refuses trusted.* and ignores names the kernel does not support or, for
// user.*, does not allow on that type.
func applyXattrs(typeflag byte, records map[string]string) (map[string]string, error) {
	var xattrs map[string]string
	for key, value := range records {
		name, ok := strings.CutPrefix(key, "SCHILY.xattr.")
		if !ok {
			continue
		}
		namespace, suffix, _ := strings.Cut(name, ".")
		switch {
		case namespace == "user" && (typeflag == tar.TypeReg || typeflag == tar.TypeDir):
		case namespace == "security":
		case name == "system.posix_acl_access", name == "system.posix_acl_default":
		default:
			continue
		}
		if suffix == "" || len(name) > xattrNameMax || len(value) > xattrSizeMax {
			return nil, errors.Errorf("invalid xattr %q", name)
		}
		if xattrs == nil {
			xattrs = map[string]string{}
		}
		xattrs[name] = value
	}
	return xattrs, nil
}

// percentEncode escapes an xattr name the way libarchive does for its
// LIBARCHIVE.xattr PAX records.
func percentEncode(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || c == '%' || c == '=' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func boundTime(t time.Time) time.Time {
	if t.Before(minApplyTime) || t.After(maxApplyTime) {
		return minApplyTime
	}
	return t
}

// applyID returns the owner lchown(2) leaves on a root-created inode: the
// kernel takes the low 32 bits and treats all-ones as "unchanged".
func applyID(id int) int {
	if uint32(id) == math.MaxUint32 {
		return 0
	}
	return int(uint32(id))
}

// mknodDev returns the device mknod(2) creates: the kernel takes the low 32
// bits of the encoded number.
func mknodDev(major, minor int64) (int64, int64) {
	dev := uint64(uint32(unix.Mkdev(uint32(major), uint32(minor))))
	return int64(unix.Major(dev)), int64(unix.Minor(dev))
}
