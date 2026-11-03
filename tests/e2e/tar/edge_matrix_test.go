package tar

import (
	"archive/tar"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"
)

func tarEdgeMatrix() []tarVector {
	sr := strings.Repeat
	mtime := time.Unix(1700000000, 0)

	reg := func(name string, size int64) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: mtime, Typeflag: tar.TypeReg}}
	}

	dir := func(name string, mode int64) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Mode: mode, ModTime: mtime, Typeflag: tar.TypeDir}}
	}

	symlink := func(name, target string) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Linkname: target, Mode: 0o777, ModTime: mtime, Typeflag: tar.TypeSymlink}}
	}

	link := func(name, target string) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Linkname: target, Mode: 0o644, ModTime: mtime, Typeflag: tar.TypeLink}}
	}

	with := func(entry tarEntry, edit func(*tar.Header)) tarEntry {
		edit(&entry.hdr)
		return entry
	}

	xattrs := func(entry tarEntry, kv ...string) tarEntry {
		return with(entry, func(h *tar.Header) {
			h.Format = tar.FormatPAX
			h.PAXRecords = map[string]string{}

			for i := 0; i < len(kv); i += 2 {
				h.PAXRecords["SCHILY.xattr."+kv[i]] = kv[i+1]
			}
		})
	}

	capNetBind := string([]byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	var manyXattrs []string

	for i := range 32 {
		manyXattrs = append(manyXattrs, fmt.Sprintf("user.k%02d", i), fmt.Sprintf("v%d", i))
	}

	vec := func(name string, entries ...tarEntry) tarVector { return tarVector{name, entries} }

	global := func(name string) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "g"}}}
	}

	var bigDir []tarEntry

	for i := range 5000 {
		bigDir = append(bigDir, reg(fmt.Sprintf("big/%04d-%s", i, sr("x", 100)), 0))
	}

	return []tarVector{
		vec("name-100", reg(sr("n", 100), 1)),
		vec("name-101", reg(sr("n", 101), 1)),
		vec("name-101-gnu", with(reg(sr("n", 101), 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		vec("name-component-255", reg(sr("c", 255), 1)),
		vec("name-prefix-split", reg(sr("p", 155)+"/"+sr("n", 100), 1)),
		vec("name-deep-path", reg(sr("0123456789/", 90)+"file", 1)),
		vec("name-dot-segments", reg("./a/./b//c", 1)),
		vec("name-special-chars", reg("a b\tc\\d\ne", 1)),
		vec("name-long-with-newline", reg(sr("n", 120)+"\n"+sr("m", 20), 1)),
		vec("name-non-utf8-gnu", with(reg("caf\xe9", 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		vec("linkname-100", symlink("s", sr("t", 100))),
		vec("linkname-101", symlink("s", sr("t", 101))),
		vec("linkname-1000", symlink("s", sr("t/", 500))),
		vec("hardlink-long-target", reg(sr("h", 150), 3), link("l", sr("h", 150))),
		vec("uid-2^21", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid = 1<<21, 1<<21 })),
		vec("uid-2^31-gnu", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid, h.Format = 1<<31, 1<<31, tar.FormatGNU })),
		vec("uid-max", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid = math.MaxUint32-1, math.MaxUint32-1 })),
		vec("mtime-nsec-pax", with(reg("f", 1), func(h *tar.Header) { h.ModTime, h.Format = time.Unix(1700000000, 123456789), tar.FormatPAX })),
		vec("mtime-zero", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(0, 0) })),
		vec("mtime-2^33", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(1<<33, 0) })),
		vec("mtime-negative", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(-1, 0) })),
		vec("device-max", with(reg("c", 0), func(h *tar.Header) {
			h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeChar, 0o600, 4095, 1<<20-1
		}), with(reg("b", 0), func(h *tar.Header) { h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeBlock, 0o600, 259, 7 })),
		vec("mode-07777", with(reg("f", 1), func(h *tar.Header) { h.Mode = 0o7777 })),
		vec("mode-0", with(reg("f", 1), func(h *tar.Header) { h.Mode = 0 }), dir("d/", 0), reg("d/f", 1)),
		vec("xattr-security-capability", xattrs(reg("f", 1), "security.capability", capNetBind)),
		vec("xattr-binary-value", xattrs(reg("f", 1), "user.bin", "\x00=\n\xff")),
		vec("xattr-newline-name", xattrs(reg("f", 1), "user.a\nb", "v")),
		vec("xattr-empty-value", xattrs(reg("f", 1), "user.empty", "")),
		vec("xattr-large-value", xattrs(reg("f", 1), "user.big", sr("x", 3000))),
		vec("xattr-many", xattrs(reg("f", 1), manyXattrs...)),
		vec("xattr-on-dir", xattrs(dir("d/", 0o755), "user.dir", "v")),
		vec("xattr-trusted-on-symlink", xattrs(symlink("s", "t"), "trusted.link", "v")),
		vec("xattr-trusted-overlay-opaque", xattrs(dir("d/", 0o755), "trusted.overlay.opaque", "y")),
		vec("xattr-libarchive-ignored", with(reg("f", 1), func(h *tar.Header) {
			h.PAXRecords = map[string]string{"LIBARCHIVE.xattr.user.la": base64.StdEncoding.EncodeToString([]byte("v"))}
		})),
		vec("size-0", reg("f", 0)),
		vec("size-511-512-513", reg("a", 511), reg("b", 512), reg("c", 513)),
		vec("size-1MiB+1", reg("f", 1<<20+1)),
		vec("size-around-2MiB-chunks", reg("a", 2<<20-1), reg("b", 2<<20+1), reg("c", 6<<20+3)),
		vec("size-4MiB-zeros", tarEntry{hdr: reg("f", 4<<20).hdr, body: make([]byte, 4<<20)}),
		vec("dir-5000-entries", bigDir...),
		vec("hardlink-to-symlink", symlink("s", "missing"), link("h", "s")),
		vec("hardlink-to-fifo", with(reg("p", 0), func(h *tar.Header) { h.Typeflag = tar.TypeFifo }), link("h", "p")),
		vec("hardlink-chain", reg("f", 3), link("l1", "f"), link("l2", "l1")),
		vec("hardlink-cross-dir", reg("d1/f", 3), link("d2/l", "d1/f")),
		vec("hardlink-own-metadata", reg("f", 3), with(link("l", "f"), func(h *tar.Header) { h.Mode, h.Uid = 0o600, 7 })),
		vec("hardlink-missing-target", link("l", "missing")),
		vec("hardlink-to-dir", dir("d/", 0o755), link("l", "d")),
		vec("symlink-absolute", symlink("s", "/etc/passwd")),
		vec("symlink-dotdot", symlink("d/s", "../../x")),
		vec("symlink-empty-target", symlink("s", "")),
		vec("parent-symlink", dir("b/", 0o755), symlink("a", "b"), reg("a/f", 3)),
		vec("parent-symlink-absolute", dir("b/", 0o755), symlink("a", "/b"), reg("a/f", 3)),
		vec("parent-symlink-escaping", symlink("a", "../../.."), reg("a/f", 3)),
		vec("parent-regular-file", reg("x", 1), reg("x/y", 1)),
		vec("override-file", reg("f", 3), with(reg("f", 5), func(h *tar.Header) { h.Mode = 0o600 })),
		vec("override-file-with-dir", reg("x", 3), dir("x/", 0o750), reg("x/y", 1)),
		vec("override-dir-with-file", dir("x/", 0o755), reg("x/y", 1), reg("x", 3)),
		vec("override-symlink-with-file", reg("t", 1), symlink("s", "t"), reg("s", 3)),
		vec("override-dir-mode", dir("d/", 0o700), reg("d/f", 1), dir("d/", 0o751)),
		vec("child-before-parent", reg("p/c", 1), dir("p/", 0o700)),
		vec("root-member", xattrs(dir("./", 0o700), "user.root", "v"), reg("f", 1)),
		vec("whiteouts", reg(".wh.gone", 0), dir("d/", 0o755), reg("d/.wh..wh..opq", 0)),
		vec("whiteout-invalid-name", reg("d/.wh..", 0)),
		vec("global-header", global("pax_global_header"), reg("f", 1)),
		vec("global-header-implies-parents", global("g/h/pax_global_header"), reg("f", 1)),
		vec("global-header-removal-replaced", reg("f", 3), global("f"), with(reg("f", 1), func(h *tar.Header) { h.Mode = 0o600 })),
		vec("global-header-removal-replaced-by-dir", reg("f", 3), global("f"), reg("f/x", 1)),
		vec("global-header-removal-under-replaced-dir", reg("d/x", 1), global("d/x"), reg("d", 3)),
	}
}
