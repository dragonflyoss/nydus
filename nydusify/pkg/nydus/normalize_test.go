/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
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
	hdrs, err := normalizeHeaders(t, encodeTar(t, file, long))
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
