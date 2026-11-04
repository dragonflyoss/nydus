package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestBuild(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			dir := env.WorkDir(t)
			blobDir := filepath.Join(dir, "blobs")
			bootstrap := filepath.Join(dir, "image.bootstrap")

			blob, _ := fixture.BuildInto(t, blobDir, bootstrap, fixture.Corpus(t, fixture.Seeded), layout)

			f := blobFile(blob).footer(t)
			if !assert.Equal(t, layout.Native, f.rawDevice()) {
				t.FailNow()
			}

			if layout.Native {
				assert.Zero(t, f.metaSize)
			} else {
				assert.NotZero(t, f.metaSize)
			}

			tags, err := erofs.DeviceTags(bootstrap)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, []string{filepath.Base(blob)}, tags) {
				t.FailNow()
			}
			if erofs.FsckDecodes(t, layout.Compressor()) {
				erofs.Fsck(t, bootstrap, blobDir)
			}

			requireVerified(t, bootstrap, blobDir, []string{blob})
			report, err := nydusCheck(t, "--blob", blob)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, "blob", report.Kind) {
				t.FailNow()
			}
			if !assert.Len(t, report.Blobs, 1) {
				t.FailNow()
			}
			if !layout.Native {
				assert.True(t, report.Blobs[0].Verified)
			}

			cached := fixture.Get(t, layout.Name)
			if !assert.Equal(t, fstest.FileSHA256(t, cached.Bootstrap), fstest.FileSHA256(t, bootstrap)) {
				t.FailNow()
			}

			assert.Equal(t, filepath.Base(cached.Blob(t)), filepath.Base(blob))
		})
	}
}

func TestBuildExclude(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	dir := env.WorkDir(t)
	source := filepath.Join(dir, "source")

	for i, name := range []string{"keep/a.bin", "drop/b.bin", "drop/nested/c.bin", "cache.tmp"} {
		path := filepath.Join(source, name)
		if !assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755)) {
			t.FailNow()
		}
		if !assert.NoError(t, os.WriteFile(path, corpus.Bytes(uint64(i), 256<<10), 0o644)) {
			t.FailNow()
		}
	}

	layout := fixture.MustLayout(t, "zstd")
	layout.Args = append(layout.Args, "--exclude", filepath.Join(source, "drop"), "--exclude", filepath.Join(source, "cache.tmp"))
	blobDir, bootstrap := filepath.Join(dir, "blobs"), filepath.Join(dir, "image.boot")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, source, layout)
	info, err := os.Stat(blob)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Less(t, info.Size(), int64(600<<10))
	m := mount.Mount(t, mount.FUSE{}, fixture.Image{Layout: layout, Bootstrap: bootstrap, BlobDir: blobDir, Blobs: []string{blob}}, mount.Options{})
	if !assert.NoDirExists(t, filepath.Join(m.Root, "drop")) {
		t.FailNow()
	}
	if !assert.NoFileExists(t, filepath.Join(m.Root, "cache.tmp")) {
		t.FailNow()
	}

	assert.Equal(t, fstest.FileSHA256(t, filepath.Join(source, "keep/a.bin")), fstest.FileSHA256(t, filepath.Join(m.Root, "keep/a.bin")))
}

func TestReproducibleBuild(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout := fixture.MustLayout(t, name)
			root := env.WorkDir(t)

			build := func(t *testing.T, src string) (bootstrap, blob string) {
				t.Helper()
				out, err := os.MkdirTemp(root, "out-")
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				bootstrap = filepath.Join(out, "boot")
				blob, _ = fixture.BuildInto(t, filepath.Join(out, "blobs"), bootstrap, src, layout)

				return bootstrap, blob
			}

			sameImage := func(t *testing.T, a, b string) {
				t.Helper()
				aBoot, aBlob := build(t, a)
				bBoot, bBlob := build(t, b)
				if !assert.Equal(t, fstest.FileSHA256(t, aBoot), fstest.FileSHA256(t, bBoot)) {
					t.FailNow()
				}

				assert.Equal(t, filepath.Base(aBlob), filepath.Base(bBlob))
			}

			t.Run("SameSourceTwice", func(t *testing.T) {
				src := filepath.Join(root, "same")
				stageReproducible(t, src, false)
				sameImage(t, src, src)
			})

			t.Run("CreationOrderDoesNotMatter", func(t *testing.T) {
				a, b := filepath.Join(root, "fwd"), filepath.Join(root, "rev")
				stageReproducible(t, a, false)
				stageReproducible(t, b, true)
				sameImage(t, a, b)
			})

			t.Run("SourcePathDoesNotMatter", func(t *testing.T) {
				a := filepath.Join(root, "p")
				b := filepath.Join(root, "a", "much", "longer", "path", "to", "the", "same", "tree")
				stageReproducible(t, a, false)
				stageReproducible(t, b, false)
				sameImage(t, a, b)
			})

			t.Run("EmptyTreeHasNoClock", func(t *testing.T) {
				a, b := filepath.Join(root, "empty-a"), filepath.Join(root, "empty-b")
				if !assert.NoError(t, os.MkdirAll(a, 0o755)) {
					t.FailNow()
				}
				if !assert.NoError(t, os.MkdirAll(b, 0o755)) {
					t.FailNow()
				}

				sameImage(t, a, b)
			})

			t.Run("RootMtimeDoesNotMatter", func(t *testing.T) {
				a, b := filepath.Join(root, "rm-a"), filepath.Join(root, "rm-b")
				stageReproducible(t, a, false)
				stageReproducible(t, b, false)

				for dir, when := range map[string]time.Time{
					a: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
					b: time.Date(2024, 11, 30, 0, 0, 0, 0, time.UTC),
				} {
					ts := unix.NsecToTimespec(when.UnixNano())
					assert.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, dir, []unix.Timespec{ts, ts}, 0))
				}

				sameImage(t, a, b)
			})

			t.Run("MergeIsStable", func(t *testing.T) {
				forward, reverse := filepath.Join(root, "forward"), filepath.Join(root, "reverse")
				stageReproducible(t, forward, false)
				stageReproducible(t, reverse, true)
				_, forwardBlob := build(t, forward)
				_, reverseBlob := build(t, reverse)
				first, second := filepath.Join(root, "merged-a"), filepath.Join(root, "merged-b")
				env.Run(t, env.Nydus(t), "merge", "--bootstrap", first, forwardBlob, reverseBlob)
				env.Run(t, env.Nydus(t), "merge", "--bootstrap", second, forwardBlob, reverseBlob)
				assert.Equal(t, fstest.FileSHA256(t, first), fstest.FileSHA256(t, second))
			})
		})
	}
}

func stageReproducible(t *testing.T, dir string, reverse bool) {
	t.Helper()
	env.MustHaveRoot(t)
	d := filepath.Join(dir, "d")
	if !assert.NoError(t, os.MkdirAll(d, 0o755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(filepath.Join(d, "base"), []byte("payload"), 0o644)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Symlink("base", filepath.Join(d, "link"))) {
		t.FailNow()
	}

	names := make([]int, 24)
	for i := range names {
		names[i] = i

		if reverse {
			names[i] = len(names) - 1 - i
		}
	}

	for _, i := range names {
		if !assert.NoError(t, os.WriteFile(filepath.Join(d, fmt.Sprintf("f%02d", i)), []byte(strings.Repeat("x", i*97)), 0o644)) {
			t.FailNow()
		}
		if !assert.NoError(t, os.Link(filepath.Join(d, "base"), filepath.Join(d, fmt.Sprintf("h%02d", i)))) {
			t.FailNow()
		}

		assert.NoError(t, unix.Setxattr(filepath.Join(d, "base"), fmt.Sprintf("user.a%02d", i), []byte("v"), 0))
	}

	ts := unix.NsecToTimespec(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())

	assert.NoError(t, filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		return unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
	}))
}

func TestNoXattr(t *testing.T) {
	t.Parallel()
	t.Run("RemovedOption", func(t *testing.T) {
		t.Parallel()
		out, err := runNydus(t, "fuse", "--mountpoint", t.TempDir(), "--no-xattr")
		if !assert.Error(t, err) {
			t.FailNow()
		}
		if !assert.Contains(t, string(out), "unexpected argument '--no-xattr'") {
			t.FailNow()
		}

		out, err = runNydus(t, "fuse", "--help")
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.NotContains(t, string(out), "--no-xattr") {
			t.FailNow()
		}

		assert.NotContains(t, string(out), "NYDUS_FUSE_NO_XATTR")
	})

	layout := fixture.MustLayout(t, "zstd")

	for _, tc := range []struct {
		name  string
		path  string
		key   string
		value []byte
	}{
		{name: "None"},
		{name: "File", path: "file", key: "user.test", value: []byte("value")},
		{name: "EmptyValue", path: "file", key: "user.empty", value: []byte{}},
		{name: "Root", path: ".", key: "user.root", value: []byte("root")},
		{name: "Directory", path: "nested", key: "user.dir", value: []byte("directory")},
		{name: "NonRootInternalName", path: "file", key: "trusted.nydus.no_xattr", value: []byte("1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env.MustHaveRoot(t)
			dir := env.WorkDir(t)
			src := filepath.Join(dir, "source")
			if !assert.NoError(t, os.MkdirAll(filepath.Join(src, "nested"), 0o755)) {
				t.FailNow()
			}
			if !assert.NoError(t, os.WriteFile(filepath.Join(src, "file"), []byte("payload"), 0o644)) {
				t.FailNow()
			}
			if tc.key != "" {
				assert.NoError(t, unix.Setxattr(filepath.Join(src, tc.path), tc.key, tc.value, 0))
			}
			if !assert.NoError(t, unix.Setxattr(src, "trusted.nydus.no_xattr", []byte("stale"), 0)) {
				t.FailNow()
			}

			img := fixture.Image{
				Name:      tc.name,
				Layout:    layout,
				Bootstrap: filepath.Join(dir, "bootstrap"),
				BlobDir:   filepath.Join(dir, "blobs"),
				Source:    src,
			}

			blob, _ := fixture.BuildInto(t, img.BlobDir, img.Bootstrap, src, layout)
			img.Blobs = []string{blob}

			for _, mode := range []mount.Mode{mount.Blob, mount.Cold} {
				t.Run(string(mode), func(t *testing.T) {
					m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mode})
					data, err := os.ReadFile(m.Path("file"))
					if !assert.NoError(t, err) {
						t.FailNow()
					}

					assert.Equal(t, []byte("payload"), data)

					for range 2 {
						if tc.key == "" {
							_, err = unix.Lgetxattr(m.Path("file"), "user.absent", nil)
							if !assert.ErrorIs(t, err, unix.EOPNOTSUPP) {
								t.FailNow()
							}

							_, err = unix.Llistxattr(m.Root, nil)
							assert.ErrorIs(t, err, unix.EOPNOTSUPP)
							continue
						}

						if !assert.Equal(t, tc.value, fstest.Xattr(t, m.Path(tc.path), tc.key)) {
							t.FailNow()
						}
						if !assert.Contains(t, fstest.ListXattr(t, m.Path(tc.path)), tc.key) {
							t.FailNow()
						}

						_, err = unix.Lgetxattr(m.Root, "trusted.nydus.no_xattr", nil)
						assert.ErrorIs(t, err, unix.ENODATA)
						assert.NotContains(t, fstest.ListXattr(t, m.Root), "trusted.nydus.no_xattr")
					}
				})
			}
		})
	}
}

func TestSubcommandHelp(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"build", "check", "export", "merge", "optimize", "fuse", "fileio"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			out, err := runNydus(t, command, "--help")
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Contains(t, string(out), "Usage:")
		})
	}
}
