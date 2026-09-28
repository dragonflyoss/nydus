/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

var normalizeMtime = time.Unix(1700000000, 0)

func tarReg(name string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, ModTime: normalizeMtime}
}

func tarDir(name string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: normalizeMtime}
}

func tarSymlink(name, target string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777, ModTime: normalizeMtime}
}

func tarLink(name, target string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0o644, ModTime: normalizeMtime}
}

func encodeTar(t *testing.T, hdrs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range hdrs {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(bytes.Repeat([]byte("x"), int(hdr.Size))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func normalizeHeaders(t *testing.T, input []byte) ([]*tar.Header, error) {
	t.Helper()
	var out bytes.Buffer
	if err := normalizeTar(&out, bytes.NewReader(input)); err != nil {
		return nil, err
	}
	var hdrs []*tar.Header
	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return hdrs, nil
		}
		if err != nil {
			t.Fatal(err)
		}
		hdrs = append(hdrs, hdr)
	}
}

func TestNormalizeTarPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []*tar.Header
		want []string // "name type linkname"
		err  string
	}{
		{"parent symlink", []*tar.Header{tarDir("b/"), tarSymlink("a", "b"), tarReg("a/f")},
			[]string{"b/ 5 ", "a 2 b", "b/f 0 "}, ""},
		{"absolute parent symlink", []*tar.Header{tarDir("etc/"), tarSymlink("l", "/etc"), tarReg("l/x")},
			[]string{"etc/ 5 ", "l 2 /etc", "etc/x 0 "}, ""},
		{"escaping parent symlink", []*tar.Header{tarSymlink("a", "../../.."), tarReg("a/f")},
			[]string{"a 2 ../../..", "f 0 "}, ""},
		{"escaping name", []*tar.Header{tarReg("../../x"), tarReg("/y")}, []string{"x 0 ", "y 0 "}, ""},
		{"root member", []*tar.Header{tarDir("./"), tarReg("f")}, []string{"f 0 "}, ""},
		{"hard link through symlink", []*tar.Header{tarDir("etc/"), tarReg("etc/passwd"), tarSymlink("l", "/etc"),
			tarLink("p", "l/passwd")}, []string{"etc/ 5 ", "etc/passwd 0 ", "l 2 /etc", "p 1 etc/passwd"}, ""},
		{"hard link to symlink", []*tar.Header{tarSymlink("s", "gone"), tarLink("h", "s")},
			[]string{"s 2 gone", "h 1 s"}, ""},
		{"hard link to missing target", []*tar.Header{tarLink("p", "nope")}, nil, "not found"},
		{"hard link to directory", []*tar.Header{tarDir("d/"), tarLink("p", "d")}, nil, "is a directory"},
		{"parent regular file", []*tar.Header{tarReg("x"), tarReg("x/y")}, nil, "not a directory"},
		{"invalid whiteout", []*tar.Header{tarReg("d/.wh..")}, nil, "invalid whiteout"},
		{"invalid root whiteout", []*tar.Header{tarReg(".wh...")}, nil, "invalid whiteout"},
		{"whiteouts kept", []*tar.Header{tarReg(".wh.gone"), tarReg("d/.wh..wh..opq")},
			[]string{".wh.gone 0 ", "d/.wh..wh..opq 0 "}, ""},
		{"empty symlink", []*tar.Header{tarSymlink("s", "")}, nil, "empty symlink"},
		{"unsupported type", []*tar.Header{{Name: "v", Typeflag: 'V'}}, nil, "unsupported type"},
		{"symlink loop", []*tar.Header{tarSymlink("l", "l/x"), tarReg("l/f")}, nil, "too many levels of symbolic links"},
		{"path too long", []*tar.Header{tarReg(strings.Repeat("a/", 2048) + "f")}, nil, "file name too long"},
		{"long name resolving short", []*tar.Header{tarReg(strings.Repeat("../", 2048) + "f")}, []string{"f 0 "}, ""},
		{"symlink target too long", []*tar.Header{tarSymlink("s", strings.Repeat("t", 4096))}, nil, "file name too long"},
		{"global header", []*tar.Header{{Name: "GlobalHead.0.0", Typeflag: tar.TypeXGlobalHeader}, tarReg("f")},
			[]string{"f 0 "}, ""},
		{"global header implies parents", []*tar.Header{{Name: "tmp/GlobalHead.1.1", Typeflag: tar.TypeXGlobalHeader}},
			[]string{"tmp/ 5 "}, ""},
		{"global header removes member", []*tar.Header{tarReg("f"), {Name: "f", Typeflag: tar.TypeXGlobalHeader}},
			nil, "no later member replaces"},
		{"global header removal replaced", []*tar.Header{tarReg("f"), {Name: "f", Typeflag: tar.TypeXGlobalHeader}, tarReg("f")},
			[]string{"f 0 ", "f 0 "}, ""},
		{"global header removal replaced by directory", []*tar.Header{tarReg("f"), {Name: "f", Typeflag: tar.TypeXGlobalHeader},
			tarReg("f/x")}, []string{"f 0 ", "f/x 0 "}, ""},
		{"global header removes directory", []*tar.Header{tarReg("d/x"), {Name: "d", Typeflag: tar.TypeXGlobalHeader}, tarDir("d/")},
			nil, "is created again"},
		{"global header removal under replaced directory", []*tar.Header{tarReg("d/x"), {Name: "d/x", Typeflag: tar.TypeXGlobalHeader},
			tarReg("d")}, []string{"d/x 0 ", "d 0 "}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdrs, err := normalizeHeaders(t, encodeTar(t, tc.in...))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got error %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, hdr := range hdrs {
				got = append(got, fmt.Sprintf("%s %c %s", hdr.Name, hdr.Typeflag, hdr.Linkname))
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeTarMetadata(t *testing.T) {
	file := tarReg("f")
	file.Mode = 0o104755
	file.ModTime = time.Unix(-1, 0)
	file.PAXRecords = map[string]string{
		"SCHILY.xattr.user.a":            "1",
		"SCHILY.xattr.trusted.overlay.x": "y",
		"SCHILY.xattr.nonamespace":       "z",
	}
	link := tarSymlink("s", "f")
	link.PAXRecords = map[string]string{"SCHILY.xattr.user.b": "1", "SCHILY.xattr.security.c": "2"}
	d1 := tarDir("d/")
	d1.PAXRecords = map[string]string{"SCHILY.xattr.user.old": "1", "SCHILY.xattr.user.both": "old"}
	d2 := tarDir("d/")
	d2.PAXRecords = map[string]string{"SCHILY.xattr.user.both": "new"}
	nsec := tarReg("n")
	nsec.ModTime = time.Unix(1, 5)
	nsec.Format = tar.FormatPAX

	hdrs, err := normalizeHeaders(t, encodeTar(t, file, link, d1, d2, nsec))
	if err != nil {
		t.Fatal(err)
	}
	f, s, d, n := hdrs[0], hdrs[1], hdrs[3], hdrs[4]
	if f.Mode != 0o4755 || !f.ModTime.Equal(time.Unix(0, 0)) {
		t.Fatalf("file mode %o mtime %v", f.Mode, f.ModTime)
	}
	if fmt.Sprint(f.PAXRecords) != fmt.Sprint(map[string]string{"SCHILY.xattr.user.a": "1"}) {
		t.Fatalf("file xattrs %v", f.PAXRecords)
	}
	if fmt.Sprint(s.PAXRecords) != fmt.Sprint(map[string]string{"SCHILY.xattr.security.c": "2"}) {
		t.Fatalf("symlink xattrs %v", s.PAXRecords)
	}
	want := map[string]string{"SCHILY.xattr.user.old": "1", "SCHILY.xattr.user.both": "new"}
	if fmt.Sprint(d.PAXRecords) != fmt.Sprint(want) {
		t.Fatalf("merged directory xattrs %v", d.PAXRecords)
	}
	if !n.ModTime.Equal(time.Unix(1, 5)) {
		t.Fatalf("sub-second mtime lost: %v", n.ModTime)
	}
}

func TestNormalizeTarNewlines(t *testing.T) {
	file := tarReg("f")
	file.PAXRecords = map[string]string{"SCHILY.xattr.user.a\nb": "v\n1", "SCHILY.xattr.user.plain": "v"}
	long := tarReg(strings.Repeat("n", 120) + "\nx")
	rich := tarReg("bad\xffname")
	rich.ModTime = time.Unix(1, 5)
	rich.Format = tar.FormatPAX
	rich.PAXRecords = map[string]string{"SCHILY.xattr.user.a": "1"}
	hdrs, err := normalizeHeaders(t, encodeTar(t, file, long, rich))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"LIBARCHIVE.xattr.user.a%0Ab": "dgox", "SCHILY.xattr.user.plain": "v"}
	if fmt.Sprint(hdrs[0].PAXRecords) != fmt.Sprint(want) {
		t.Fatalf("xattr records %v", hdrs[0].PAXRecords)
	}
	if hdrs[1].Format != tar.FormatGNU || hdrs[1].Name != long.Name {
		t.Fatalf("newline path written as %v %q", hdrs[1].Format, hdrs[1].Name)
	}
	// A GNU header carries a raw PAX header for what only PAX can hold.
	r := hdrs[2]
	if r.Name != rich.Name || !r.ModTime.Equal(rich.ModTime) || r.PAXRecords["SCHILY.xattr.user.a"] != "1" {
		t.Fatalf("GNU member written as %q %v %v", r.Name, r.ModTime, r.PAXRecords)
	}
}

func TestNormalizeTarRestampsDirs(t *testing.T) {
	dir := tarDir("d/")
	dir.ModTime = time.Unix(5, 0)
	other := tarDir("e/")
	other.ModTime = time.Unix(6, 0)
	for _, tc := range []struct {
		name string
		in   []*tar.Header
		want string // the restamp member, "name type linkname mtime"
		err  string
	}{
		{"replaced by file", []*tar.Header{dir, tarReg("d")}, "d 1 d 5", ""},
		{"replaced by symlink to dir", []*tar.Header{other, dir, tarSymlink("d", "e")}, "e/ 5  5", ""},
		{"replaced by dangling symlink", []*tar.Header{dir, tarSymlink("d", "gone")}, "", "no longer resolves"},
		{"parent replaced by file", []*tar.Header{tarDir("p/"), tarDir("p/d/"), tarReg("p")}, "", "no longer resolves"},
		{"unchanged", []*tar.Header{dir, tarReg("d/f"), dir}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdrs, err := normalizeHeaders(t, encodeTar(t, tc.in...))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got error %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if len(hdrs) > len(tc.in) {
				last := hdrs[len(hdrs)-1]
				got = fmt.Sprintf("%s %c %s %d", last.Name, last.Typeflag, last.Linkname, last.ModTime.Unix())
			}
			if got != tc.want {
				t.Fatalf("got restamp %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeTarSetgidImplicitDir(t *testing.T) {
	dir := tarDir("s/")
	dir.Mode, dir.Gid = 0o2755, 7
	hdrs, err := normalizeHeaders(t, encodeTar(t, dir, tarReg("s/a/b/f")))
	if err != nil {
		t.Fatal(err)
	}
	// Only the directory mkdir(2) creates in the setgid one inherits.
	if len(hdrs) != 3 || hdrs[1].Name != "s/a/" || hdrs[1].Gid != 7 || hdrs[1].Mode != 0o755 {
		t.Fatalf("implicit directories written as %v", hdrs)
	}
}

func TestNormalizeTarKeepsUnchangedOwner(t *testing.T) {
	dir := tarDir("d/")
	dir.Uid, dir.Gid = 5, 6
	merge := tarDir("d/")
	merge.Uid, merge.Gid = -1, 8
	file := tarReg("d/f")
	file.Uid, file.Gid = 9, 10
	link := tarLink("d/h", "d/f")
	link.Uid, link.Gid = 11, -1
	sgid := tarDir("s/")
	sgid.Mode, sgid.Gid = 0o2755, 7
	inherit := tarReg("s/f")
	inherit.Uid, inherit.Gid = -1, -1
	fresh := tarReg("g")
	fresh.Uid, fresh.Gid = -1, -1
	hdrs, err := normalizeHeaders(t, encodeTar(t, dir, merge, file, link, sgid, inherit, fresh))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, hdr := range hdrs {
		got = append(got, fmt.Sprintf("%s %d:%d", hdr.Name, hdr.Uid, hdr.Gid))
	}
	// lchown(2) keeps an owner given as -1: the merged directory's, the
	// hard link target's, and the group a setgid directory hands down.
	want := []string{"d/ 5:6", "d/ 5:8", "d/f 9:10", "d/h 11:10", "s/ 0:7", "s/f 0:7", "g 0:0"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNormalizeTarXattrNames(t *testing.T) {
	acl := "\x02\x00\x00\x00" + "\x01\x00\x06\x00\xff\xff\xff\xff"
	for _, tc := range []struct {
		name   string
		hdr    *tar.Header
		xattrs map[string]string
		want   string // the kept xattr names, or the error
	}{
		{"no namespace", tarReg("f"), map[string]string{"user": "v", "security": "v", "x.y": "v"}, ""},
		{"empty user suffix", tarReg("f"), map[string]string{"user.": "v"}, "invalid xattr"},
		{"empty security suffix", tarSymlink("s", "t"), map[string]string{"security.": "v"}, "invalid xattr"},
		{"empty name", tarReg("f"), map[string]string{"": "v"}, "invalid xattr"},
		// lsetxattr(2) checks sizes before it looks for a handler.
		{"long unsupported name", tarReg("f"), map[string]string{"x." + strings.Repeat("n", 254): "v"}, "invalid xattr"},
		{"large value on symlink", tarSymlink("s", "t"), map[string]string{"user.a": strings.Repeat("v", 65537)}, "invalid xattr"},
		{"trusted dropped", tarReg("f"), map[string]string{"trusted.overlay.opaque": "y"}, ""},
		{"user on symlink dropped", tarSymlink("s", "t"), map[string]string{"user.a": "v"}, ""},
		{"acl kept", tarDir("d/"), map[string]string{"system.posix_acl_access": acl, "system.posix_acl_default": acl},
			"system.posix_acl_access system.posix_acl_default"},
		{"acl on symlink dropped", tarSymlink("s", "t"), map[string]string{"system.posix_acl_access": acl}, ""},
		{"empty acl dropped", tarReg("f"), map[string]string{"system.posix_acl_default": ""}, ""},
		{"default acl on file", tarReg("f"), map[string]string{"system.posix_acl_default": acl}, "non-directory"},
		{"malformed acl", tarReg("f"), map[string]string{"system.posix_acl_access": "\x02\x00\x00\x00\x01"}, "invalid xattr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.hdr.PAXRecords = map[string]string{}
			for k, v := range tc.xattrs {
				tc.hdr.PAXRecords["SCHILY.xattr."+k] = v
			}
			hdrs, err := normalizeHeaders(t, encodeTar(t, tc.hdr))
			var got string
			if err != nil {
				got = err.Error()
			} else {
				var names []string
				for key := range hdrs[len(hdrs)-1].PAXRecords {
					names = append(names, strings.TrimPrefix(key, "SCHILY.xattr."))
				}
				slices.Sort(names)
				got = strings.Join(names, " ")
			}
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeTarDevices(t *testing.T) {
	dev := &tar.Header{Name: "d", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 0x1234, Devminor: 0x123456, ModTime: normalizeMtime}
	hdrs, err := normalizeHeaders(t, encodeTar(t, dev))
	if err != nil {
		t.Fatal(err)
	}
	// The kernel keeps 12 bits of major and 20 of minor.
	if hdrs[0].Devmajor != 0x234 || hdrs[0].Devminor != 0x23456 {
		t.Fatalf("device %x:%x", hdrs[0].Devmajor, hdrs[0].Devminor)
	}
}

func TestNormalizeTarGzip(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(encodeTar(t, tarReg("f"))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	hdrs, err := normalizeHeaders(t, gz.Bytes())
	if err != nil || len(hdrs) != 1 || hdrs[0].Name != "f" {
		t.Fatalf("gzip layer: %v %v", hdrs, err)
	}
	corrupt := slices.Clone(gz.Bytes())
	corrupt[len(corrupt)-8] ^= 1 // the CRC-32 in the gzip trailer
	if _, err := normalizeHeaders(t, corrupt); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt gzip layer accepted: %v", err)
	}
}

func TestNormalizeTarDrainsTrailingData(t *testing.T) {
	input := bytes.NewReader(append(encodeTar(t, tarReg("f")), bytes.Repeat([]byte("garbage "), 1000)...))
	if err := normalizeTar(io.Discard, input); err != nil {
		t.Fatal(err)
	}
	if input.Len() != 0 {
		t.Fatalf("%d bytes left unread", input.Len())
	}
}

func TestNormalizeTarRejectsTruncatedMember(t *testing.T) {
	input := encodeTar(t, tarReg("f"))
	if err := normalizeTar(io.Discard, bytes.NewReader(input[:512])); err == nil {
		t.Fatal("truncated member accepted")
	}
}
