package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockFile(t *testing.T, path, data string) string {
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestSaveBootstrap(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, dir string) (string, string)
		expect func(t *testing.T, dir, path, source string, err error)
	}{
		{
			name: "reject symlink loop destination",
			mock: func(t *testing.T, dir string) (string, string) {
				path := filepath.Join(dir, "loop")
				if err := os.Symlink(path, path); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "source"), "bootstrap")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
		{
			name: "reject destination in missing dir",
			mock: func(t *testing.T, dir string) (string, string) {
				return filepath.Join(dir, "missing", "image.boot"), mockFile(t, filepath.Join(dir, "source"), "bootstrap")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
		{
			name: "preserve 0644 destination mode",
			mock: func(t *testing.T, dir string) (string, string) {
				path := mockFile(t, filepath.Join(dir, "target"), "old")
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "source"), "new")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o644), info.Mode().Perm())
				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))

				assert.NoError(saveBootstrap(path, path))
				info, err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o644), info.Mode().Perm())
				data, err = os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))
			},
		},
		{
			name: "preserve 0640 destination mode",
			mock: func(t *testing.T, dir string) (string, string) {
				path := mockFile(t, filepath.Join(dir, "target"), "old")
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "source"), "new")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o640), info.Mode().Perm())
				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))

				assert.NoError(saveBootstrap(path, path))
				info, err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o640), info.Mode().Perm())
				data, err = os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))
			},
		},
		{
			name: "preserve 0444 destination mode",
			mock: func(t *testing.T, dir string) (string, string) {
				path := mockFile(t, filepath.Join(dir, "target"), "old")
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "source"), "new")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o444), info.Mode().Perm())
				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))

				assert.NoError(saveBootstrap(path, path))
				info, err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(os.FileMode(0o444), info.Mode().Perm())
				data, err = os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("new", string(data))
			},
		},
		{
			name: "stream large bootstrap",
			mock: func(t *testing.T, dir string) (string, string) {
				source := filepath.Join(dir, "source")
				file, err := os.Create(source)
				if err != nil {
					t.Fatal(err)
				}

				if err := file.Truncate(16 << 20); err != nil {
					t.Fatal(err)
				}

				if _, err := file.WriteAt([]byte("tail"), 16<<20-4); err != nil {
					t.Fatal(err)
				}

				if err := file.Close(); err != nil {
					t.Fatal(err)
				}

				return filepath.Join(dir, "target"), source
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}

				assert.Equal(int64(16<<20), info.Size())
				assert.Equal(os.FileMode(0o600), info.Mode().Perm())

				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}

				tail := make([]byte, 4)
				_, err = file.ReadAt(tail, 16<<20-4)
				assert.NoError(err)
				assert.NoError(file.Close())
				assert.Equal("tail", string(tail))

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
		{
			name: "keep destination when source is missing",
			mock: func(t *testing.T, dir string) (string, string) {
				return mockFile(t, filepath.Join(dir, "target"), "old"), filepath.Join(dir, "missing")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("old", string(data))

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
		{
			name: "keep destination when source is a directory",
			mock: func(t *testing.T, dir string) (string, string) {
				return mockFile(t, filepath.Join(dir, "target"), "old"), dir
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("old", string(data))

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
		{
			name: "replace input without changing retained link",
			mock: func(t *testing.T, dir string) (string, string) {
				path := mockFile(t, filepath.Join(dir, "image.boot"), "original")
				if err := os.Link(path, filepath.Join(dir, "retained.boot")); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "final.boot"), "compacted")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				data, err := os.ReadFile(path)
				assert.NoError(err)
				assert.Equal("compacted", string(data))

				data, err = os.ReadFile(filepath.Join(dir, "retained.boot"))
				assert.NoError(err)
				assert.Equal("original", string(data))
			},
		},
		{
			name: "remove temporary file when rename fails",
			mock: func(t *testing.T, dir string) (string, string) {
				path := filepath.Join(dir, "directory")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}

				return path, mockFile(t, filepath.Join(dir, "final.boot"), "compacted")
			},
			expect: func(t *testing.T, dir, path, source string, err error) {
				assert := assert.New(t)
				assert.Error(err)

				matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
				assert.NoError(err)
				assert.Empty(matches)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, source := tc.mock(t, dir)
			err := saveBootstrap(path, source)

			tc.expect(t, dir, path, source, err)
		})
	}
}
