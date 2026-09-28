/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"math"
	"path"
	"slices"
	"strconv"
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

// maxLinksFollowed is the kernel's MAXSYMLINKS: lstat(2) fails with ELOOP
// after following that many symlinks within one path.
const maxLinksFollowed = 40

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
// and each member is written again as a PAX header, or a GNU one for a name
// PAX cannot carry. Archives Go or Apply reject are rejected, with the
// departures a single layer needs: GNU sparse and contiguous members are
// the regular files Go reads them as, dumpdir members are directories, and
// OCI whiteouts pass through as plain files for a merge to interpret. A
// gzip stream is decompressed first, as nydus build sniffs it too.
func normalizeTar(w io.Writer, r io.Reader) error {
	input := bufio.NewReader(r)
	var layer io.Reader = input
	if magic, _ := input.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(input)
		if err != nil {
			return errors.Wrap(err, "read gzip layer")
		}
		layer = gz
	}
	tr := tar.NewReader(layer)
	tw := tar.NewWriter(w)
	root := newTarDir()
	root.removed = map[string]bool{}
	var dirs []dirTime
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read layer tar")
		}
		hdrs, err := root.apply(hdr)
		if err != nil {
			return errors.Wrapf(err, "layer tar member %q", hdr.Name)
		}
		for _, out := range hdrs {
			if err := writeHeader(tw, w, out); err != nil {
				return err
			}
		}
		if len(hdrs) == 0 || hdr.Typeflag == tar.TypeXGlobalHeader {
			// Of a global header, only the directories it implied were written.
			continue
		}
		out := hdrs[len(hdrs)-1]
		if out.Typeflag == tar.TypeDir {
			dirs = append(dirs, dirTime{path.Clean(hdr.Name), out.ModTime})
		}
		if out.Typeflag == tar.TypeReg {
			if _, err := io.Copy(tw, tr); err != nil {
				return errors.Wrapf(err, "copy layer tar member %q", hdr.Name)
			}
		}
	}
	if len(root.removed) > 0 {
		return errors.Errorf("global header removes %q, which no later member replaces",
			slices.Sorted(maps.Keys(root.removed))[0])
	}
	if err := root.restampDirs(tw, w, dirs); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return errors.Wrap(err, "finish layer tar")
	}
	// Whatever follows the end-of-archive marker is ignored, but must be
	// consumed so the writer feeding r is not blocked. Draining the gzip
	// stream to its end verifies its checksum, as containerd does.
	if _, err := io.Copy(io.Discard, layer); err != nil {
		return errors.Wrap(err, "drain layer tar")
	}
	_, err := io.Copy(io.Discard, input)
	return errors.Wrap(err, "drain layer tar")
}

// writeHeader writes a normalized member header to tw, which writes to w.
func writeHeader(tw *tar.Writer, w io.Writer, hdr *tar.Header) error {
	if hdr.Format == tar.FormatGNU {
		if err := writeGNUExtensions(tw, w, hdr); err != nil {
			return errors.Wrapf(err, "write layer tar member %q", hdr.Name)
		}
	}
	return errors.Wrapf(tw.WriteHeader(hdr), "write layer tar member %q", hdr.Name)
}

// dirTime is a directory member, by the name it was archived under, whose
// mtime Apply sets again once the whole layer is applied.
type dirTime struct {
	name  string
	mtime time.Time
}

// restampDirs mirrors the last pass of Apply, which sets each directory
// member's mtime again, resolving its name through the symlinks of the
// finished tree: a name that no longer resolves fails the layer, and one
// that now resolves elsewhere restamps whatever is there. Inodes whose
// mtime changes are written again: a directory as a directory member, which
// merges, anything else as a hard link to itself, whose metadata nydus build
// stamps on the inode.
func (root *tarNode) restampDirs(tw *tar.Writer, w io.Writer, dirs []dirTime) error {
	var order []*tarNode
	stamps := map[*tarNode]dirTime{}
	for _, dir := range dirs {
		p, err := root.rootPath(dir.name)
		if err != nil {
			return errors.Wrapf(err, "layer tar directory %q", dir.name)
		}
		if p == "/" {
			continue
		}
		node, err := root.lookup(p)
		if err != nil {
			return errors.Wrapf(err, "layer tar directory %q", dir.name)
		}
		if node == nil {
			return errors.Errorf("layer tar directory %q no longer resolves", dir.name)
		}
		if _, ok := stamps[node]; !ok {
			order = append(order, node)
		}
		stamps[node] = dirTime{p[1:], dir.mtime}
	}
	for _, node := range order {
		stamp := stamps[node]
		if stamp.mtime.Equal(node.mtime) {
			continue
		}
		node.mtime = stamp.mtime
		hdr := &tar.Header{Name: stamp.name, Mode: node.mode, Uid: node.uid, Gid: node.gid, ModTime: node.mtime}
		var xattrs map[string]string
		if node.typeflag == tar.TypeDir {
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			xattrs = node.xattrs
		} else {
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = hdr.Name
		}
		encodeHeader(hdr, xattrs)
		if err := writeHeader(tw, w, hdr); err != nil {
			return err
		}
	}
	return nil
}

// writeGNUExtensions moves what only PAX records carry of a GNU member, its
// xattrs and sub-second mtime, into a PAX extended header written to w
// ahead of it: Go pairs no PAX records with a GNU header, but nydus build
// applies both to the member that follows.
func writeGNUExtensions(tw *tar.Writer, w io.Writer, hdr *tar.Header) error {
	var data bytes.Buffer
	for _, key := range slices.Sorted(maps.Keys(hdr.PAXRecords)) {
		data.WriteString(paxRecord(key, hdr.PAXRecords[key]))
	}
	hdr.PAXRecords = nil
	if nsec := hdr.ModTime.Nanosecond(); nsec != 0 {
		// Last in sorted order too, after the upper-case xattr keys.
		// boundTime keeps the time past the epoch, so no sign correction.
		data.WriteString(paxRecord("mtime", strings.TrimRight(fmt.Sprintf("%d.%09d", hdr.ModTime.Unix(), nsec), "0")))
	}
	if data.Len() == 0 {
		return nil
	}
	// Pad the previous member so the extended header starts on a block.
	if err := tw.Flush(); err != nil {
		return err
	}
	blk := make([]byte, 512)
	copy(blk, "PaxHeader")
	copy(blk[100:], "0000644\x00")
	copy(blk[108:], "0000000\x00")
	copy(blk[116:], "0000000\x00")
	copy(blk[124:], fmt.Sprintf("%011o\x00", data.Len()))
	copy(blk[136:], "00000000000\x00")
	blk[156] = tar.TypeXHeader
	copy(blk[257:], "ustar\x0000")
	copy(blk[148:], "        ")
	sum := 0
	for _, c := range blk {
		sum += int(c)
	}
	copy(blk[148:], fmt.Sprintf("%06o\x00 ", sum))
	data.Write(make([]byte, -data.Len()&511))
	if _, err := w.Write(blk); err != nil {
		return err
	}
	_, err := w.Write(data.Bytes())
	return err
}

// paxRecord encodes a PAX record, whose length prefix counts itself.
func paxRecord(key, value string) string {
	size := len(key) + len(value) + 3
	size += len(strconv.Itoa(size))
	record := strconv.Itoa(size) + " " + key + "=" + value + "\n"
	if len(record) != size {
		record = strconv.Itoa(len(record)) + " " + key + "=" + value + "\n"
	}
	return record
}

// tarNode is what later members observe of an applied inode. Hard links
// share one node.
type tarNode struct {
	typeflag byte
	linkname string
	mode     int64
	uid, gid int
	mtime    time.Time
	xattrs   map[string]string
	children map[string]*tarNode
	// removed is kept on the root only: the paths global headers removed
	// that no later member has replaced yet, and whether each held a
	// directory.
	removed map[string]bool
}

// newTarDir returns a directory as Apply and nydus build create one
// implicitly: 0755 root:root. Apply dates it to the time it ran, which no
// layer can reproduce, so it gets the epoch, as nydus build gives it.
func newTarDir() *tarNode {
	return &tarNode{typeflag: tar.TypeDir, mode: 0o755, mtime: minApplyTime, children: map[string]*tarNode{}}
}

// apply records hdr the way archive.Apply lands it and returns the members
// to emit for it, none for one Apply ignores: the member itself, after any
// implicit directory nydus build would not create as Apply does.
func (root *tarNode) apply(hdr *tar.Header) ([]*tar.Header, error) {
	typeflag := hdr.Typeflag
	switch typeflag {
	case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
	// tar.Reader already reports the legacy TypeRegA as TypeReg or TypeDir.
	case tar.TypeCont, tar.TypeGNUSparse:
		typeflag = tar.TypeReg
	case typeGNUDumpDir:
		typeflag = tar.TypeDir
	case tar.TypeXGlobalHeader:
		// Apply resolves it like any member before ignoring it.
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
	if len(target) >= unix.PathMax {
		return nil, errors.Wrap(unix.ENAMETOOLONG, "member path")
	}
	for _, comp := range strings.Split(target[1:], "/") {
		if len(comp) > unix.NAME_MAX {
			return nil, errors.New("name component too long")
		}
	}
	global := typeflag == tar.TypeXGlobalHeader
	parent, implicit, err := root.mkparent(parentPath, global)
	if err != nil {
		return nil, err
	}
	if err := validateWhiteout(target); err != nil {
		return nil, err
	}

	name := path.Base(target)
	existing := parent.children[name]
	if global {
		// Apply removes whatever the name held before ignoring the header.
		// A stream of members cannot express that, so it must be replaced
		// later.
		if existing != nil {
			delete(parent.children, name)
			root.forgetRemovedUnder(target[1:])
			root.removed[target[1:]] = existing.typeflag == tar.TypeDir
		}
		return implicit, nil
	}
	if err := root.replaceRemoved(target[1:], typeflag == tar.TypeDir); err != nil {
		return nil, err
	}
	if existing != nil && (existing.typeflag != tar.TypeDir || typeflag != tar.TypeDir) {
		delete(parent.children, name)
		existing = nil
	}

	out := &tar.Header{
		Typeflag: typeflag,
		Name:     target[1:],
		Mode:     hdr.Mode & 0o7777,
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
		if len(hdr.Linkname) >= unix.PathMax {
			return nil, errors.Wrap(unix.ENAMETOOLONG, "symlink target")
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
		node, err = root.lookup(linkTarget)
		if err != nil {
			return nil, errors.Wrapf(err, "hard link target %q", hdr.Linkname)
		}
		if node == nil {
			return nil, errors.Errorf("hard link target %q not found", hdr.Linkname)
		}
		if node.typeflag == tar.TypeDir {
			return nil, errors.Errorf("hard link target %q is a directory", hdr.Linkname)
		}
		out.Linkname = linkTarget[1:]
	}
	if node != existing && typeflag != tar.TypeLink && parent.mode&0o2000 != 0 {
		// A new inode in a setgid directory takes the directory's group.
		node.gid = parent.gid
	}
	out.Uid = applyID(hdr.Uid, node.uid)
	out.Gid = applyID(hdr.Gid, node.gid)

	xattrs, err := applyXattrs(node.typeflag, hdr.PAXRecords)
	if err != nil {
		return nil, err
	}
	if typeflag == tar.TypeDir {
		// Apply sets xattrs on the directory it merges into.
		if node.xattrs != nil {
			maps.Copy(node.xattrs, xattrs)
			xattrs = node.xattrs
		}
		node.xattrs = xattrs
	}
	// Apply sets the member's metadata on the inode, a hard link's too,
	// except that chmod does not apply to a symlink.
	if node.typeflag != tar.TypeSymlink || typeflag == tar.TypeSymlink {
		node.mode = out.Mode
	}
	node.uid, node.gid, node.mtime = out.Uid, out.Gid, out.ModTime
	encodeHeader(out, xattrs)
	parent.children[name] = node
	return append(implicit, out), nil
}

// encodeHeader stores xattrs in out's PAX records and picks the format
// that carries out's names to nydus build.
func encodeHeader(out *tar.Header, xattrs map[string]string) {
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
}

// lookup finds p like lstat(2): symlinks in leading components are
// followed within the root, the last component is not. A nil node means p
// does not exist. Like lstat(2), it fails for a path of PATH_MAX bytes or
// more (Apply's is longer by its root, so it gives up a little sooner) and
// after following too many symlinks; both bound the work a hostile layer
// can demand.
func (root *tarNode) lookup(p string) (*tarNode, error) {
	return root.lookupDepth(p, 0)
}

func (root *tarNode) lookupDepth(p string, followed int) (*tarNode, error) {
	if followed > maxLinksFollowed {
		return nil, unix.ELOOP
	}
	if len(p) >= unix.PathMax {
		return nil, unix.ENAMETOOLONG
	}
	comps := strings.Split(strings.TrimPrefix(path.Clean("/"+p), "/"), "/")
	cur := root
	for i, comp := range comps {
		if comp == "" {
			return cur, nil
		}
		node := cur.children[comp]
		if node == nil || i == len(comps)-1 {
			return node, nil
		}
		switch node.typeflag {
		case tar.TypeDir:
			cur = node
		case tar.TypeSymlink:
			link := node.linkname
			if !path.IsAbs(link) {
				link = path.Join("/", path.Join(comps[:i]...), link)
			}
			return root.lookupDepth(path.Join(append([]string{link}, comps[i+1:]...)...), followed+1)
		default:
			return nil, nil
		}
	}
	return cur, nil
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
	node, err := root.lookup(p)
	if err != nil {
		return "", false, err
	}
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
// ones as the implicit directories Apply creates. mkdir(2) in a setgid
// directory inherits its group, which nydus build cannot know, so those
// are returned as members to emit; Apply's chmod clears the setgid bit
// they would inherit too. With emitAll, every directory it creates is
// returned, for a member that is not emitted to imply them.
func (root *tarNode) mkparent(p string, emitAll bool) (*tarNode, []*tar.Header, error) {
	var implicit []*tar.Header
	cur := root
	var dir string
	for _, comp := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if comp == "" {
			continue
		}
		dir = path.Join(dir, comp)
		node := cur.children[comp]
		if node == nil {
			if err := root.replaceRemoved(dir, true); err != nil {
				return nil, nil, err
			}
			node = newTarDir()
			if cur.mode&0o2000 != 0 {
				node.gid = cur.gid
			}
			if emitAll || cur.mode&0o2000 != 0 {
				out := &tar.Header{Typeflag: tar.TypeDir, Name: dir + "/", Mode: node.mode, Gid: node.gid, ModTime: node.mtime}
				encodeHeader(out, nil)
				implicit = append(implicit, out)
			}
			cur.children[comp] = node
		} else if node.typeflag != tar.TypeDir {
			return nil, nil, errors.Errorf("parent %q is not a directory", p)
		}
		cur = node
	}
	return cur, implicit, nil
}

// replaceRemoved records that a member, or an implicit directory when dir
// is set, lands on p. If a global header removed p, nydus build replaces
// what p held as Apply does, unless both are directories: it would merge
// them, keeping the entries Apply removed.
func (root *tarNode) replaceRemoved(p string, dir bool) error {
	if !dir {
		// A non-directory replaces p's subtree, with whatever was removed
		// in it.
		root.forgetRemovedUnder(p)
	}
	wasDir, ok := root.removed[p]
	if !ok {
		return nil
	}
	if wasDir && dir {
		return errors.Errorf("directory %q removed by a global header is created again", p)
	}
	delete(root.removed, p)
	return nil
}

// forgetRemovedUnder drops the pending removals below p.
func (root *tarNode) forgetRemovedUnder(p string) {
	maps.DeleteFunc(root.removed, func(removed string, _ bool) bool { return strings.HasPrefix(removed, p+"/") })
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

// applyXattrs keeps the xattrs Apply sets on an inode of type typeflag,
// checking each name in the order lsetxattr(2) does and dropping what
// Apply ignores: trusted.*, which containerd refuses to set, user.* on an
// inode other than a regular file or directory, names no handler serves,
// and POSIX ACLs on a symlink. Only an ACL's framing is checked; the
// kernel's validation of its entries, and its folding of a minimal ACL
// into the mode, are not reproduced.
func applyXattrs(typeflag byte, records map[string]string) (map[string]string, error) {
	var xattrs map[string]string
	for key, value := range records {
		name, ok := strings.CutPrefix(key, "SCHILY.xattr.")
		if !ok || strings.HasPrefix(name, "trusted.") {
			continue
		}
		if name == "" || len(name) > xattrNameMax || len(value) > xattrSizeMax {
			return nil, errors.Errorf("invalid xattr %q", name)
		}
		switch {
		case strings.HasPrefix(name, "user."):
			if typeflag != tar.TypeReg && typeflag != tar.TypeDir {
				continue
			}
			if name == "user." {
				return nil, errors.Errorf("invalid xattr %q", name)
			}
		case strings.HasPrefix(name, "security."):
			if name == "security." {
				return nil, errors.Errorf("invalid xattr %q", name)
			}
		case name == "system.posix_acl_access", name == "system.posix_acl_default":
			// An empty value removes the ACL, which a new inode lacks.
			if typeflag == tar.TypeSymlink || value == "" {
				continue
			}
			if name == "system.posix_acl_default" && typeflag != tar.TypeDir {
				return nil, errors.New("default ACL on a non-directory")
			}
			if !validACLHeader(value) {
				return nil, errors.Errorf("invalid xattr %q", name)
			}
		default:
			continue
		}
		if xattrs == nil {
			xattrs = map[string]string{}
		}
		xattrs[name] = value
	}
	return xattrs, nil
}

// validACLHeader reports whether value has the framing of the kernel's
// POSIX ACL xattr: a little-endian version 2 header and whole 8-byte
// entries. lsetxattr(2) refuses anything else.
func validACLHeader(value string) bool {
	return len(value) >= 12 && (len(value)-4)%8 == 0 && value[:4] == "\x02\x00\x00\x00"
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

// applyID returns the owner lchown(2) leaves on an inode owned by current:
// the kernel takes the low 32 bits and treats all-ones as "unchanged".
func applyID(id, current int) int {
	if uint32(id) == math.MaxUint32 {
		return current
	}
	return int(uint32(id))
}

// mknodDev returns the device mknod(2) creates on Linux: Go encodes the
// numbers as glibc's makedev and the kernel keeps the low 32 bits, 12 of
// major and 20 of minor.
func mknodDev(major, minor int64) (int64, int64) {
	return int64(uint32(major) & 0xfff), int64(uint32(minor) & 0xfffff)
}
