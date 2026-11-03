// containerdBreakouts and containerdApplyCases copy the archives of tests in
// containerd's pkg/archive (tar_test.go, issues_test.go), Copyright The
// containerd Authors, licensed under the Apache License, Version 2.0.

package tar

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/stretchr/testify/assert"
)

func containerdBreakouts(t *testing.T) []tarCase {
	t.Helper()
	tc := tartest.TarContext{}.WithUIDGID(0, 0).WithModTime(time.Unix(1700000000, 0))
	expected := []byte("unbroken")
	etc := []tartest.WriterToTar{tc.Dir("etc", 0o755), tc.File("/etc/passwd", []byte("inside"), 0o644)}
	usersEtc := []tartest.WriterToTar{tc.Dir("etc", 0o755), tc.File("/etc/passwd", []byte("all users"), 0o644)}

	with := func(lower []tartest.WriterToTar, w ...tartest.WriterToTar) tartest.WriterToTar {
		return tartest.TarAll(append(append([]tartest.WriterToTar{}, lower...), w...)...)
	}

	cases := []struct {
		name string
		w    tartest.WriterToTar
	}{
		{"SymlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0o755), tc.Symlink("/etc", "localetc"),
			tc.File("/localetc/unbroken", expected, 0o644))},
		{"SymlinkUpAndOut", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/dummy/../etc", "localetc"), tc.File("/localetc/unbroken", expected, 0o644))},
		{"SymlinkMultipleAbsolute", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("/dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0o644))},
		{"SymlinkMultipleRelative", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("./dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0o644))},
		{"SymlinkEmptyFile", tartest.TarAll(tc.Dir("etc", 0o755), tc.File("etc/emptied", []byte("notempty"), 0o644),
			tc.Symlink("/etc", "localetc"), tc.File("/localetc/emptied", []byte{}, 0o644))},
		{"HardlinkRelative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("breakouts", 0o755), tc.Symlink("../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"HardlinkDownAndOut", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("breakouts", 0o755), tc.Dir("downandout", 0o755), tc.Symlink("../downandout/../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"HardlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkRelativeLong", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("../../../../../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkRelativeUpAndOut", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("upandout/../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkDirectRelative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Link("../../../../../etc/passwd", "localpasswd"))},
		{"HardlinkDirectAbsolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkParentDirectory", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", ".."), tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkEmptyFilename", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", ""), tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkParentRelative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", "localetc/sub/.."), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkSlashEnded", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("localetc/", 0o770), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkOverrideDirectory", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0o755)},
			tc.Symlink("/etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkOverrideDirectoryRelative", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0o755)},
			tc.Symlink("../../etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"DirectoryOverrideSymlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("/etc", "localetc")},
			tc.Dir("/localetc/", 0o755), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"DirectoryOverrideSymlinkAndHardlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("etc", "localetc"),
			tc.Link("/etc/passwd", "/localetc/localpasswd")},
			tc.Dir("/localetc/", 0o755), tc.File("/localetc/localpasswd", []byte("different"), 0o644))},
		{"WhiteoutRootParent", with(etc, tc.File(".wh...", []byte{}, 0o644))},
		{"WhiteoutParent", with(etc, tc.File("etc/.wh...", []byte{}, 0o644))},
		{"WhiteoutRoot", with(etc, tc.File(".wh..", []byte{}, 0o644))},
		{"WhiteoutCurrentDirectory", with(etc, tc.File("etc/.wh..", []byte{}, 0o644))},
		{"WhiteoutSymlink", with(append(usersEtc, tc.Symlink("/etc", "localetc")),
			tc.File(".wh.localetc", []byte{}, 0o644))},
		{"WhiteoutSymlinkPath", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0o644),
			tc.Symlink("/etc", "localetc")), tc.File("localetc/.wh.whitedout", []byte{}, 0o644))},
		{"WhiteoutDirectoryName", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0o644),
			tc.Symlink("/etc", "localetc")), tc.File(".wh.etc/somefile", []byte("non-empty"), 0o644))},
		{"WhiteoutDeadSymlinkParent", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("localetc/.wh.etc", []byte{}, 0o644))},
		{"WhiteoutRelativePath", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("dne/../.wh.etc", []byte{}, 0o644))},
		{"HardlinkSymlinkBeforeCreateTarget", tartest.TarAll(tc.Dir("etc", 0o770), tc.Symlink("/etc/passwd", "localpasswd"),
			tc.Link("localpasswd", "localpasswd-dup"), tc.File("/etc/passwd", []byte("after"), 0o644))},
		{"HardlinkSymlinkRelative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("../../../../../etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"HardlinkSymlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"HardlinkSymlinkChmod", tartest.TarAll(tc.Symlink("/tmp/perm400", "/tmp/also-exists-outside-root"),
			tc.Link("/tmp/also-exists-outside-root", "sketchylink"))},
		{"DirectoryCreation", with([]tartest.WriterToTar{tc.Dir("/etc/", 0o755)},
			tc.Dir("/etc/subdir", 0o755), tc.Dir("/etc/subdir2/", 0o755), tc.Dir("/etc/subdir2/more", 0o755),
			tc.Dir("/other/noparent-1/1", 0o755), tc.Dir("/other/noparent-2/2/", 0o755))},
	}

	out := make([]tarCase, 0, len(cases))

	for _, c := range cases {
		r := tartest.TarFromWriterTo(c.w)
		data, err := io.ReadAll(r)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.NoError(t, r.Close())
		out = append(out, tarCase{c.name, data})
	}

	return out
}

func containerdApplyCases(t *testing.T) []tarCase {
	t.Helper()
	prefixHeader := []byte("\x1f\x8b\x08\x08\x44\x21\x68\x59\x00\x03\x74\x2e\x74\x61\x72\x00\x4b\xcb\xcf\x67\xa0\x35\x30\x80\x00\x86\x06\x10\x47\x01\xc1\x37\x40\x00\x54\xb6\xb1\xa1\xa9\x99\x09\x48\x25\x1d\x40\x69\x71\x49\x62\x91\x02\xe5\x76\xa1\x79\x84\x21\x91\xd6\x80\x72\xaf\x8f\x82\x51\x30\x0a\x46\x36\x00\x00\xf0\x1c\x1e\x95\x00\x06\x00\x00")
	cases := []tarCase{{"PrefixHeaderReadable", prefixHeader}}

	for _, xattr := range [][3]string{
		{"TarWithXattrUser", "user.key", "value"},
		{"TarWithXattrSelinux", "security.selinux", "unconfined_u:object_r:default_t:s0\x00"},
	} {
		tc := tartest.TarContext{}.WithUIDGID(0, 0).WithModTime(time.Unix(1700000000, 0)).
			WithXattrs(map[string]string{xattr[1]: xattr[2]})

		r := tartest.TarFromWriterTo(tartest.TarAll(tc.File("/file", []byte{}, 0o755)))
		data, err := io.ReadAll(r)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		cases = append(cases, tarCase{xattr[0], data})
	}

	base := fstest.Apply(
		fstest.CreateDir("/etc/", 0o755),
		fstest.CreateFile("/etc/hosts", []byte("127.0.0.1 localhost"), 0o644),
		fstest.Link("/etc/hosts", "/etc/hosts.allow"),
		fstest.CreateDir("/usr/local/lib", 0o755),
		fstest.CreateFile("/usr/local/lib/libnothing.so", []byte{0x00, 0x00}, 0o755),
		fstest.Symlink("libnothing.so", "/usr/local/lib/libnothing.so.2"),
		fstest.CreateDir("/home", 0o755),
		fstest.CreateDir("/home/derek", 0o700),
	)

	symlinks := [][]fstest.Applier{
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0o755), fstest.CreateFile("/bin/superbinary", []byte{0, 0}, 0o755),
				fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1"),
				fstest.Symlink("../bin/superbinary", "/bin/other2"), fstest.Symlink("superbinary", "/bin/other3")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0o755), fstest.CreateDir("/sbin/", 0o755),
				fstest.CreateFile("/sbin/superbinary", []byte{0, 0}, 0o755),
				fstest.Symlink("/sbin/superbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1"),
				fstest.Symlink("superbinary", "/bin/other2")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0o755), fstest.CreateDir("/sbin/", 0o755),
				fstest.CreateFile("/sbin/superbinary", []byte{0, 0}, 0o755),
				fstest.Symlink("../sbin/superbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0o755), fstest.CreateFile("/bin/actualbinary", []byte{0, 0}, 0o755),
				fstest.Symlink("actualbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1"),
				fstest.Symlink("superbinary", "/bin/other2")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Remove("/bin/other2"),
				fstest.Symlink("/bin/superbinary", "/bin/other1"), fstest.Symlink("superbinary", "/bin/other2")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0o755), fstest.CreateFile("/bin/actualbinary", []byte{0, 0}, 0o755),
				fstest.Symlink("actualbinary", "/bin/myapp")),
			fstest.Apply(fstest.Remove("/bin/myapp"), fstest.CreateDir("/bin/myapp", 0o755)),
		},
	}

	for i, steps := range symlinks {
		dir := t.TempDir()

		for j, step := range steps {
			if !assert.NoError(t, step.Apply(dir)) {
				t.FailNow()
			}

			cases = append(cases, tarCase{fmt.Sprintf("Symlinks-%d-%d", i, j), writeDiff(t, dir)})
		}
	}

	for i, links := range []fstest.Applier{
		fstest.Apply(fstest.Symlink("../other", "/home/derek/other"), fstest.Symlink("../../etc", "/home/derek/etc"),
			fstest.Symlink("up/../../other", "/home/derek/updown")),
		fstest.Symlink("../../../breakout", "/home/derek/breakout"),
		fstest.Symlink("../../breakout", "/breakout"),
		fstest.Symlink("etc/../../upandout", "/breakout"),
		fstest.Symlink("derek/../../../downandout", "/home/breakout"),
		fstest.Symlink("/etc", "localetc"),
	} {
		dir := t.TempDir()
		if !assert.NoError(t, fstest.Apply(base, links).Apply(dir)) {
			t.FailNow()
		}

		cases = append(cases, tarCase{fmt.Sprintf("RelativeSymlinks-%d", i), writeDiff(t, dir)})
	}

	return cases
}

func writeDiff(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if !assert.NoError(t, archive.WriteDiff(context.Background(), &buf, "", dir)) {
		t.FailNow()
	}

	return buf.Bytes()
}
