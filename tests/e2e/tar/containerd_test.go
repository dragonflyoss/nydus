// containerdBreakouts and containerdApplyVectors copy the archives of tests in
// containerd's pkg/archive (tar_test.go, issues_test.go), Copyright The
// containerd Authors, licensed under the Apache License, Version 2.0, refer
// to https://github.com/containerd/containerd/blob/main/LICENSE.

package tar

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// containerdBreakouts returns containerd's path-escape archives. A case's
// pre-existing lower tree is written as leading members of the same archive,
// which Apply resolves the same way; containerd's validators are replaced by
// the reference differential, which also sees Apply stamp tartest's fixed
// 0777 link mode onto each hard link target.
func containerdBreakouts(t *testing.T) []encodedVector {
	t.Helper()
	tc := tartest.TarContext{}.WithUIDGID(0, 0).WithModTime(time.Unix(1700000000, 0))
	expected := []byte("unbroken")
	etc := []tartest.WriterToTar{tc.Dir("etc", 0o755), tc.File("/etc/passwd", []byte("inside"), 0o644)}
	usersEtc := []tartest.WriterToTar{tc.Dir("etc", 0o755), tc.File("/etc/passwd", []byte("all users"), 0o644)}
	with := func(lower []tartest.WriterToTar, upper ...tartest.WriterToTar) tartest.WriterToTar {
		return tartest.TarAll(slices.Concat(lower, upper)...)
	}

	cases := []struct {
		name    string
		members tartest.WriterToTar
	}{
		{"symlink absolute", tartest.TarAll(tc.Dir("etc", 0o755), tc.Symlink("/etc", "localetc"),
			tc.File("/localetc/unbroken", expected, 0o644))},
		{"symlink up and out", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/dummy/../etc", "localetc"), tc.File("/localetc/unbroken", expected, 0o644))},
		{"symlink multiple absolute", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("/dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0o644))},
		{"symlink multiple relative", tartest.TarAll(tc.Dir("etc", 0o755), tc.Dir("dummy", 0o755),
			tc.Symlink("/etc", "/dummy/etc"), tc.Symlink("./dummy/etc", "localetc"),
			tc.File("/dummy/etc/unbroken", expected, 0o644))},
		{"symlink empty file", tartest.TarAll(tc.Dir("etc", 0o755), tc.File("etc/emptied", []byte("notempty"), 0o644),
			tc.Symlink("/etc", "localetc"), tc.File("/localetc/emptied", []byte{}, 0o644))},
		{"hardlink relative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("breakouts", 0o755), tc.Symlink("../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"hardlink down and out", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("breakouts", 0o755), tc.Dir("downandout", 0o755), tc.Symlink("../downandout/../../etc", "breakouts/d1"),
			tc.Link("/breakouts/d1/passwd", "breakouts/mypasswd"))},
		{"hardlink absolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"hardlink relative long", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("../../../../../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"hardlink relative up and out", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("upandout/../../../etc", "localetc"), tc.Link("/localetc/passwd", "localpasswd"))},
		{"hardlink direct relative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Link("../../../../../etc/passwd", "localpasswd"))},
		{"hardlink direct absolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Link("/etc/passwd", "localpasswd"))},
		{"symlink parent directory", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", ".."), tc.Link("/etc/passwd", "localpasswd"))},
		{"symlink empty filename", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", ""), tc.Link("/etc/passwd", "localpasswd"))},
		{"symlink parent relative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/", "localetc/sub/.."), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"symlink slash ended", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Dir("localetc/", 0o770), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"symlink override directory", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0o755)},
			tc.Symlink("/etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"symlink override directory relative", with([]tartest.WriterToTar{etc[0], etc[1], tc.Dir("/localetc/", 0o755)},
			tc.Symlink("../../etc", "localetc"), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"directory override symlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("/etc", "localetc")},
			tc.Dir("/localetc/", 0o755), tc.Link("/etc/passwd", "/localetc/localpasswd"))},
		{"directory override symlink and hardlink", with([]tartest.WriterToTar{etc[0], etc[1], tc.Symlink("etc", "localetc"),
			tc.Link("/etc/passwd", "/localetc/localpasswd")},
			tc.Dir("/localetc/", 0o755), tc.File("/localetc/localpasswd", []byte("different"), 0o644))},
		{"whiteout root parent", with(etc, tc.File(".wh...", []byte{}, 0o644))},
		{"whiteout parent", with(etc, tc.File("etc/.wh...", []byte{}, 0o644))},
		{"whiteout root", with(etc, tc.File(".wh..", []byte{}, 0o644))},
		{"whiteout current directory", with(etc, tc.File("etc/.wh..", []byte{}, 0o644))},
		{"whiteout symlink", with(append(usersEtc, tc.Symlink("/etc", "localetc")),
			tc.File(".wh.localetc", []byte{}, 0o644))},
		{"whiteout symlink path", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0o644),
			tc.Symlink("/etc", "localetc")), tc.File("localetc/.wh.whitedout", []byte{}, 0o644))},
		{"whiteout directory name", with(append(usersEtc, tc.File("/etc/whitedout", []byte("ahhhh whiteout"), 0o644),
			tc.Symlink("/etc", "localetc")), tc.File(".wh.etc/somefile", []byte("non-empty"), 0o644))},
		{"whiteout dead symlink parent", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("localetc/.wh.etc", []byte{}, 0o644))},
		{"whiteout relative path", with(append(usersEtc, tc.Symlink("/dne", "localetc")),
			tc.File("dne/../.wh.etc", []byte{}, 0o644))},
		{"hardlink symlink before create target", tartest.TarAll(tc.Dir("etc", 0o770), tc.Symlink("/etc/passwd", "localpasswd"),
			tc.Link("localpasswd", "localpasswd-dup"), tc.File("/etc/passwd", []byte("after"), 0o644))},
		{"hardlink symlink relative", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("../../../../../etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"hardlink symlink absolute", tartest.TarAll(tc.Dir("etc", 0o770), tc.File("/etc/passwd", []byte("inside"), 0o644),
			tc.Symlink("/etc/passwd", "passwdlink"), tc.Link("/passwdlink", "localpasswd"))},
		{"hardlink symlink chmod", tartest.TarAll(tc.Symlink("/tmp/perm400", "/tmp/also-exists-outside-root"),
			tc.Link("/tmp/also-exists-outside-root", "sketchylink"))},
		// TestApplyTar.
		{"directory creation", with([]tartest.WriterToTar{tc.Dir("/etc/", 0o755)},
			tc.Dir("/etc/subdir", 0o755), tc.Dir("/etc/subdir2/", 0o755), tc.Dir("/etc/subdir2/more", 0o755),
			tc.Dir("/other/noparent-1/1", 0o755), tc.Dir("/other/noparent-2/2/", 0o755))},
	}

	// Encode each case.
	encoded := make([]encodedVector, 0, len(cases))
	for _, c := range cases {
		r := tartest.TarFromWriterTo(c.members)
		data, err := io.ReadAll(r)
		assert.NoError(t, err, c.name)
		assert.NoError(t, r.Close())
		encoded = append(encoded, encodedVector{name: c.name, data: data})
	}

	return encoded
}

// containerdApplyVectors returns the archives of containerd's other Apply
// tests: TestPrefixHeaderReadable (issues_test.go), TestTarWithXattr, and
// the trees TestSymlinks and TestRelativeSymlinks diff, each step written
// whole by archive.WriteDiff.
func containerdApplyVectors(t *testing.T) []encodedVector {
	t.Helper()
	prefixHeader := []byte("\x1f\x8b\x08\x08\x44\x21\x68\x59\x00\x03\x74\x2e\x74\x61\x72\x00\x4b\xcb\xcf\x67\xa0\x35\x30\x80\x00\x86\x06\x10\x47\x01\xc1\x37\x40\x00\x54\xb6\xb1\xa1\xa9\x99\x09\x48\x25\x1d\x40\x69\x71\x49\x62\x91\x02\xe5\x76\xa1\x79\x84\x21\x91\xd6\x80\x72\xaf\x8f\x82\x51\x30\x0a\x46\x36\x00\x00\xf0\x1c\x1e\x95\x00\x06\x00\x00")
	cases := []encodedVector{{"prefix header readable", prefixHeader}}

	// Write TestTarWithXattr's file with each of its xattrs.
	for _, xattr := range [][3]string{
		{"tar with xattr user", "user.key", "value"},
		{"tar with xattr selinux", "security.selinux", "unconfined_u:object_r:default_t:s0\x00"},
	} {
		tc := tartest.TarContext{}.WithUIDGID(0, 0).WithModTime(time.Unix(1700000000, 0)).
			WithXattrs(map[string]string{xattr[1]: xattr[2]})
		r := tartest.TarFromWriterTo(tartest.TarAll(tc.File("/file", []byte{}, 0o755)))
		data, err := io.ReadAll(r)
		assert.NoError(t, err)
		cases = append(cases, encodedVector{name: xattr[0], data: data})
	}

	// Write the tree of each TestSymlinks step.
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
			assert.NoError(t, step.Apply(dir))
			cases = append(cases, encodedVector{name: fmt.Sprintf("symlinks-%d-%d", i, j), data: writeDiff(t, dir)})
		}
	}

	// Write the base tree of TestRelativeSymlinks with each of its links.
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
		assert.NoError(t, fstest.Apply(base, links).Apply(dir))
		cases = append(cases, encodedVector{name: fmt.Sprintf("relative symlinks-%d", i), data: writeDiff(t, dir)})
	}

	return cases
}

// writeDiff archives dir whole the way containerd's differ writes layers.
func writeDiff(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	assert.NoError(t, archive.WriteDiff(context.Background(), &buf, "", dir))

	return buf.Bytes()
}

// TestContinuityFSSuite runs continuity's filesystem suite, which
// containerd's differ is tested with, against nydus: after every step the
// whole tree is written as one layer by containerd's archive.WriteDiff,
// converted by nydus build, and the suite compares the FUSE mount with its
// own copy of the tree.
func TestContinuityFSSuite(t *testing.T) {
	util.SkipUnlessRoot(t, "the suite creates root-owned trees")

	// The suite's steps share the applier's tree, so only the suite as a
	// whole runs alongside the other tests.
	t.Parallel()
	fstest.FSSuite(t, &nydusLayerApplier{t: t})
}

// nydusLayerApplier converts the suite's cumulative tree into a single
// nydus layer after every change. FSSuite hands it no *testing.T of its own,
// so a mount failure is reported against the suite's test rather than the
// step's.
type nydusLayerApplier struct {
	// t is the suite's test, which the packing and mounting helpers report to.
	t *testing.T

	// tree is the directory the suite's changes accumulate in.
	tree string
}

// TestContext creates the tree the suite's changes accumulate in and returns
// the cleanup that removes it.
func (a *nydusLayerApplier) TestContext(ctx context.Context) (context.Context, func(), error) {
	tree, err := os.MkdirTemp("", "fssuite-tree-")
	if err != nil {
		return nil, nil, err
	}
	a.tree = tree

	return ctx, func() { _ = os.RemoveAll(tree) }, nil
}

// Apply applies change to the tree, writes the whole tree as one layer and
// returns its nydus mount with the cleanup that unmounts it.
func (a *nydusLayerApplier) Apply(ctx context.Context, change fstest.Applier) (string, func(), error) {
	// Apply the change and write the whole tree as one layer.
	if err := change.Apply(a.tree); err != nil {
		return "", nil, err
	}

	var diff bytes.Buffer
	if err := archive.WriteDiff(ctx, &diff, "", a.tree); err != nil {
		return "", nil, err
	}

	// Give the first member an xattr: continuity never compares xattrs but
	// lists them, and nydus answers listxattr with EOPNOTSUPP on an image
	// without any; the differ itself only writes security.capability.
	var layer bytes.Buffer
	tr, tw := tar.NewReader(&diff), tar.NewWriter(&layer)
	for first := true; ; first = false {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
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

	// Convert the layer and mount it.
	workDir, err := os.MkdirTemp("", "fssuite-layer-")
	if err != nil {
		return "", nil, err
	}
	blob := filepath.Join(workDir, "layer.blob")
	if err := packLayer(a.t, &layer, blob, blobLayout{}); err != nil {
		_ = os.RemoveAll(workDir)
		return "", nil, err
	}

	mountpoint := filepath.Join(workDir, "mnt")
	unmount := util.MountNydusBlob(a.t, nydusBin, blob, mountpoint)

	return mountpoint, func() {
		unmount()
		_ = os.RemoveAll(workDir)
	}, nil
}
