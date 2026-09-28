// containerdBreakouts and containerdApplyCases copy the archives of tests in
// containerd's pkg/archive (tar_test.go, issues_test.go), Copyright The
// containerd Authors, licensed under the Apache License, Version 2.0.

package tar

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e"
	"github.com/stretchr/testify/require"
)

// containerdBreakouts returns containerd's path-escape archives. A case's
// pre-existing lower tree is written as leading members of the same archive,
// which Apply resolves the same way; containerd's validators are replaced by
// the reference differential, which also sees Apply stamp tartest's fixed
// 0777 link mode onto each hard link target.
func containerdBreakouts(t *testing.T) []tarCase {
	t.Helper()
	tc := tartest.TarContext{}.WithUIDGID(0, 0).WithModTime(time.Unix(1700000000, 0))
	expected := []byte("unbroken")
	etc := []tartest.WriterToTar{tc.Dir("etc", 0755), tc.File("/etc/passwd", []byte("inside"), 0644)}
	usersEtc := []tartest.WriterToTar{tc.Dir("etc", 0755), tc.File("/etc/passwd", []byte("all users"), 0644)}
	with := func(lower []tartest.WriterToTar, w ...tartest.WriterToTar) tartest.WriterToTar {
		return tartest.TarAll(append(append([]tartest.WriterToTar{}, lower...), w...)...)
	}

	cases := []struct {
		name string
		w    tartest.WriterToTar
	}{
		{"SymlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0755), tc.Symlink("/etc", "localetc"),
			tc.File("/localetc/unbroken", expected, 0644))},
		{"SymlinkUpAndOut", tartest.TarAll(tc.Dir("etc", 0755), tc.Dir("dummy", 0755),
			tc.Symlink("/dummy/../etc", "localetc"), tc.File("/localetc/unbroken", expected, 0644))},
		{"SymlinkMultipleAbsolute", tartest.TarAll(tc.Dir("etc", 0755), tc.Dir("dummy", 0755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("/dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0644))},
		{"SymlinkMultipleRelative", tartest.TarAll(tc.Dir("etc", 0755), tc.Dir("dummy", 0755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("./dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0644))},
		{"SymlinkEmptyFile", tartest.TarAll(tc.Dir("etc", 0755), tc.File("etc/emptied", []byte("notempty"), 0644),
			tc.Symlink("/etc", "localetc"), tc.File("/localetc/emptied", []byte{}, 0644))},
		{"HardlinkRelative", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Dir("breakouts", 0755), tc.Symlink("../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"HardlinkDownAndOut", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Dir("breakouts", 0755), tc.Dir("downandout", 0755), tc.Symlink("../downandout/../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"HardlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("/etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkRelativeLong", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("../../../../../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkRelativeUpAndOut", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("upandout/../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"HardlinkDirectRelative", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Link("../../../../../etc/passwd", "localpasswd"))},
		{"HardlinkDirectAbsolute", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkParentDirectory", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("/etc/", ".."), tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkEmptyFilename", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("/etc/", ""), tc.Link("/etc/passwd", "localpasswd"))},
		{"SymlinkParentRelative", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("/etc/", "localetc/sub/.."), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkSlashEnded", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Dir("localetc/", 0770), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkOverrideDirectory", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0755)},
			tc.Symlink("/etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"SymlinkOverrideDirectoryRelative", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0755)},
			tc.Symlink("../../etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"DirectoryOverrideSymlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("/etc", "localetc")},
			tc.Dir("/localetc/", 0755), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"DirectoryOverrideSymlinkAndHardlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("etc", "localetc"),
			tc.Link("/etc/passwd", "/localetc/localpasswd")},
			tc.Dir("/localetc/", 0755), tc.File("/localetc/localpasswd", []byte("different"), 0644))},
		{"WhiteoutRootParent", with(etc, tc.File(".wh...", []byte{}, 0644))},
		{"WhiteoutParent", with(etc, tc.File("etc/.wh...", []byte{}, 0644))},
		{"WhiteoutRoot", with(etc, tc.File(".wh..", []byte{}, 0644))},
		{"WhiteoutCurrentDirectory", with(etc, tc.File("etc/.wh..", []byte{}, 0644))},
		{"WhiteoutSymlink", with(append(usersEtc, tc.Symlink("/etc", "localetc")),
			tc.File(".wh.localetc", []byte{}, 0644))},
		{"WhiteoutSymlinkPath", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0644),
			tc.Symlink("/etc", "localetc")), tc.File("localetc/.wh.whitedout", []byte{}, 0644))},
		{"WhiteoutDirectoryName", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0644),
			tc.Symlink("/etc", "localetc")), tc.File(".wh.etc/somefile", []byte("non-empty"), 0644))},
		{"WhiteoutDeadSymlinkParent", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("localetc/.wh.etc", []byte{}, 0644))},
		{"WhiteoutRelativePath", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("dne/../.wh.etc", []byte{}, 0644))},
		{"HardlinkSymlinkBeforeCreateTarget", tartest.TarAll(tc.Dir("etc", 0770), tc.Symlink("/etc/passwd", "localpasswd"),
			tc.Link("localpasswd", "localpasswd-dup"), tc.File("/etc/passwd", []byte("after"), 0644))},
		{"HardlinkSymlinkRelative", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("../../../../../etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"HardlinkSymlinkAbsolute", tartest.TarAll(tc.Dir("etc", 0770), tc.File("/etc/passwd", []byte("inside"), 0644),
			tc.Symlink("/etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"HardlinkSymlinkChmod", tartest.TarAll(tc.Symlink("/tmp/perm400", "/tmp/also-exists-outside-root"),
			tc.Link("/tmp/also-exists-outside-root", "sketchylink"))},
		// TestApplyTar.
		{"DirectoryCreation", with([]tartest.WriterToTar{tc.Dir("/etc/", 0755)},
			tc.Dir("/etc/subdir", 0755), tc.Dir("/etc/subdir2/", 0755), tc.Dir("/etc/subdir2/more", 0755),
			tc.Dir("/other/noparent-1/1", 0755), tc.Dir("/other/noparent-2/2/", 0755))},
	}

	out := make([]tarCase, 0, len(cases))
	for _, c := range cases {
		r := tartest.TarFromWriterTo(c.w)
		data, err := io.ReadAll(r)
		require.NoError(t, err, c.name)
		require.NoError(t, r.Close())
		out = append(out, tarCase{c.name, data})
	}
	return out
}

// containerdApplyCases returns the archives of containerd's other Apply
// tests: TestPrefixHeaderReadable (issues_test.go), TestTarWithXattr, and
// the trees TestSymlinks and TestRelativeSymlinks diff, each step written
// whole by archive.WriteDiff.
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
		r := tartest.TarFromWriterTo(tartest.TarAll(tc.File("/file", []byte{}, 0755)))
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		cases = append(cases, tarCase{xattr[0], data})
	}

	base := fstest.Apply(
		fstest.CreateDir("/etc/", 0755),
		fstest.CreateFile("/etc/hosts", []byte("127.0.0.1 localhost"), 0644),
		fstest.Link("/etc/hosts", "/etc/hosts.allow"),
		fstest.CreateDir("/usr/local/lib", 0755),
		fstest.CreateFile("/usr/local/lib/libnothing.so", []byte{0x00, 0x00}, 0755),
		fstest.Symlink("libnothing.so", "/usr/local/lib/libnothing.so.2"),
		fstest.CreateDir("/home", 0755),
		fstest.CreateDir("/home/derek", 0700),
	)
	symlinks := [][]fstest.Applier{
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0755), fstest.CreateFile("/bin/superbinary", []byte{0, 0}, 0755),
				fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1"),
				fstest.Symlink("../bin/superbinary", "/bin/other2"), fstest.Symlink("superbinary", "/bin/other3")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0755), fstest.CreateDir("/sbin/", 0755),
				fstest.CreateFile("/sbin/superbinary", []byte{0, 0}, 0755),
				fstest.Symlink("/sbin/superbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1"),
				fstest.Symlink("superbinary", "/bin/other2")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0755), fstest.CreateDir("/sbin/", 0755),
				fstest.CreateFile("/sbin/superbinary", []byte{0, 0}, 0755),
				fstest.Symlink("../sbin/superbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Symlink("/bin/superbinary", "/bin/other1")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0755), fstest.CreateFile("/bin/actualbinary", []byte{0, 0}, 0755),
				fstest.Symlink("actualbinary", "/bin/superbinary"), fstest.Symlink("../bin/superbinary", "/bin/other1"),
				fstest.Symlink("superbinary", "/bin/other2")),
			fstest.Apply(fstest.Remove("/bin/other1"), fstest.Remove("/bin/other2"),
				fstest.Symlink("/bin/superbinary", "/bin/other1"), fstest.Symlink("superbinary", "/bin/other2")),
		},
		{
			fstest.Apply(fstest.CreateDir("/bin/", 0755), fstest.CreateFile("/bin/actualbinary", []byte{0, 0}, 0755),
				fstest.Symlink("actualbinary", "/bin/myapp")),
			fstest.Apply(fstest.Remove("/bin/myapp"), fstest.CreateDir("/bin/myapp", 0755)),
		},
	}
	for i, steps := range symlinks {
		dir := t.TempDir()
		for j, step := range steps {
			require.NoError(t, step.Apply(dir))
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
		require.NoError(t, fstest.Apply(base, links).Apply(dir))
		cases = append(cases, tarCase{fmt.Sprintf("RelativeSymlinks-%d", i), writeDiff(t, dir)})
	}
	return cases
}

// writeDiff archives dir whole the way containerd's differ writes layers.
func writeDiff(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, archive.WriteDiff(context.Background(), &buf, "", dir))
	return buf.Bytes()
}

// TestContinuityFSSuite runs continuity's filesystem suite, which
// containerd's differ is tested with, against nydus: after every step the
// whole tree is written as one layer by containerd's archive.WriteDiff,
// converted by nydus.Pack, and the suite compares the FUSE mount with its
// own copy of the tree.
func TestContinuityFSSuite(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the suite creates root-owned trees")
	}
	// The suite's steps share the applier's tree, so only the suite as a
	// whole runs alongside the other tests.
	t.Parallel()
	fstest.FSSuite(t, &nydusLayerApplier{t: t, nydusBin: e2e.MustLookupExecutable(t, "nydus")})
}

// nydusLayerApplier converts the suite's cumulative tree into a single
// nydus layer after every change. FSSuite hands it no *testing.T of its own,
// so a harness failure in packing or mounting aborts the whole test binary.
type nydusLayerApplier struct {
	t        *testing.T
	nydusBin string
	tree     string
}

func (a *nydusLayerApplier) TestContext(ctx context.Context) (context.Context, func(), error) {
	tree, err := os.MkdirTemp("", "fssuite-tree-")
	if err != nil {
		return nil, nil, err
	}
	a.tree = tree
	return ctx, func() { _ = os.RemoveAll(tree) }, nil
}

func (a *nydusLayerApplier) Apply(ctx context.Context, change fstest.Applier) (string, func(), error) {
	if err := change.Apply(a.tree); err != nil {
		return "", nil, err
	}
	var diff bytes.Buffer
	if err := archive.WriteDiff(ctx, &diff, "", a.tree); err != nil {
		return "", nil, err
	}
	// continuity never compares xattrs but lists them, and nydus answers
	// listxattr with EOPNOTSUPP on an image without any, so the first member
	// carries one; the differ itself only writes security.capability.
	var layer bytes.Buffer
	tr, tw := tar.NewReader(&diff), tar.NewWriter(&layer)
	for first := true; ; first = false {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		if first {
			hdr.Format = tar.FormatPAX
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr.user.e2e"] = "1"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", nil, err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return "", nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", nil, err
	}
	work, err := os.MkdirTemp("", "fssuite-layer-")
	if err != nil {
		return "", nil, err
	}
	blob := filepath.Join(work, "layer.blob")
	if err := packLayer(a.t, a.nydusBin, &layer, blob, tarLayout{}); err != nil {
		_ = os.RemoveAll(work)
		return "", nil, err
	}
	mnt := filepath.Join(work, "mnt")
	unmount := e2e.MountNydus(a.t, a.nydusBin, "", blob, mnt)
	return mnt, func() {
		unmount()
		_ = os.RemoveAll(work)
	}, nil
}
