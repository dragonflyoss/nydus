package rule

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestFilesystemRuleName(t *testing.T) {
	rule := &FilesystemRule{}
	require.Equal(t, "filesystem", rule.Name())
}

func TestNodeString(t *testing.T) {
	hash := []byte{0xde, 0xad, 0xbe, 0xef}
	node := Node{
		Path:    "/etc/test.conf",
		Size:    1024,
		Mode:    0644,
		Rdev:    0,
		Symlink: "",
		UID:     1000,
		GID:     1000,
		Xattrs:  map[string][]byte{"security.selinux": []byte("system_u")},
		Hash:    hash,
	}
	s := node.String()
	require.Contains(t, s, "/etc/test.conf")
	require.Contains(t, s, "1024")
	require.Contains(t, s, hex.EncodeToString(hash))
	require.Contains(t, s, "security.selinux")
}

func TestNodeStringEmpty(t *testing.T) {
	node := Node{}
	s := node.String()
	require.Contains(t, s, "path: ")
	require.Contains(t, s, "size: 0")
}

func TestNodeStringSymlink(t *testing.T) {
	node := Node{
		Path:    "/usr/bin/python",
		Symlink: "/usr/bin/python3",
		Mode:    os.ModeSymlink | 0777,
	}
	s := node.String()
	require.Contains(t, s, "/usr/bin/python3")
	require.Contains(t, s, "/usr/bin/python")
}

func TestNodeStringNilXattrs(t *testing.T) {
	node := Node{
		Path:   "/tmp/test",
		Xattrs: nil,
	}
	s := node.String()
	require.Contains(t, s, "xattrs: map[]")
}

// --- ManifestRule Tests ---

func TestManifestRuleName(t *testing.T) {
	rule := &ManifestRule{}
	require.Equal(t, "manifest", rule.Name())
}

func TestBootstrapRuleName(t *testing.T) {
	rule := &BootstrapRule{}
	require.Equal(t, "bootstrap", rule.Name())
}

func TestValidateOCIValid(t *testing.T) {
	rule := &ManifestRule{}
	image := &parser.Image{
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{{}, {}},
		},
		Config: ocispec.Image{
			RootFS: ocispec.RootFS{
				DiffIDs: []digest.Digest{
					digest.FromString("a"),
					digest.FromString("b"),
				},
			},
		},
	}
	require.NoError(t, rule.validateOCI(image))
}

func TestValidateOCIMismatchedDiffIDs(t *testing.T) {
	rule := &ManifestRule{}
	image := &parser.Image{
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{{}, {}},
		},
		Config: ocispec.Image{
			RootFS: ocispec.RootFS{
				DiffIDs: []digest.Digest{digest.FromString("a")},
			},
		},
	}
	err := rule.validateOCI(image)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid diff ids")
}

func TestValidateNydusValid(t *testing.T) {
	rule := &ManifestRule{}
	image := &parser.Image{
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{
				{
					MediaType:   utils.MediaTypeNydusBlob,
					Annotations: map[string]string{utils.LayerAnnotationNydusBlob: "true"},
				},
				{
					Annotations: map[string]string{utils.LayerAnnotationNydusBootstrap: "true"},
				},
			},
		},
		Config: ocispec.Image{
			RootFS: ocispec.RootFS{
				DiffIDs: []digest.Digest{digest.FromString("a"), digest.FromString("b")},
			},
		},
	}
	require.NoError(t, rule.validateNydus(image))
}

func TestValidateNydusInvalidBootstrap(t *testing.T) {
	rule := &ManifestRule{}
	image := &parser.Image{
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{
				{Annotations: map[string]string{}},
			},
		},
		Config: ocispec.Image{
			RootFS: ocispec.RootFS{
				DiffIDs: []digest.Digest{digest.FromString("a")},
			},
		},
	}
	err := rule.validateNydus(image)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid bootstrap layer")
}

func TestValidateNydusInvalidBlob(t *testing.T) {
	rule := &ManifestRule{}
	image := &parser.Image{
		Manifest: ocispec.Manifest{
			Layers: []ocispec.Descriptor{
				{
					MediaType:   "wrong",
					Annotations: map[string]string{},
				},
				{
					Annotations: map[string]string{utils.LayerAnnotationNydusBootstrap: "true"},
				},
			},
		},
		Config: ocispec.Image{
			RootFS: ocispec.RootFS{
				DiffIDs: []digest.Digest{digest.FromString("a"), digest.FromString("b")},
			},
		},
	}
	err := rule.validateNydus(image)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid blob layer")
}

func TestValidateConfigEqual(t *testing.T) {
	rule := &ManifestRule{}
	cfg := ocispec.ImageConfig{
		Env:        []string{"PATH=/usr/bin"},
		Cmd:        []string{"/bin/sh"},
		WorkingDir: "/",
	}
	src := &parser.Image{Config: ocispec.Image{}}
	src.Config.Config = cfg
	tgt := &parser.Image{Config: ocispec.Image{}}
	tgt.Config.Config = cfg
	require.NoError(t, rule.validateConfig(src, tgt))
}

func TestValidateConfigNotEqual(t *testing.T) {
	rule := &ManifestRule{}
	src := &parser.Image{Config: ocispec.Image{}}
	src.Config.Config.Env = []string{"A=1"}
	tgt := &parser.Image{Config: ocispec.Image{}}
	tgt.Config.Config.Env = []string{"B=2"}
	err := rule.validateConfig(src, tgt)
	require.Error(t, err)
	require.Contains(t, err.Error(), "should be equal")
}

func TestValidateNilParsed(t *testing.T) {
	rule := &ManifestRule{}
	require.NoError(t, rule.validate(nil))
}

// --- Filesystem walk & verify tests ---

func TestWalk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "subdir", "file2.txt"), []byte("world"), 0644))
	require.NoError(t, os.Symlink("file1.txt", filepath.Join(dir, "link")))

	rule := &FilesystemRule{}
	nodes, err := rule.walk(dir)
	require.NoError(t, err)

	require.Contains(t, nodes, "/")
	require.Contains(t, nodes, "/file1.txt")
	require.Contains(t, nodes, "/subdir")
	require.Contains(t, nodes, "/subdir/file2.txt")
	require.Contains(t, nodes, "/link")

	require.Equal(t, int64(5), nodes["/file1.txt"].Size)
	require.Equal(t, int64(5), nodes["/subdir/file2.txt"].Size)
	require.NotNil(t, nodes["/file1.txt"].Hash)
	require.NotNil(t, nodes["/subdir/file2.txt"].Hash)
}

func TestWalkEmptyDir(t *testing.T) {
	dir := t.TempDir()
	rule := &FilesystemRule{}
	nodes, err := rule.walk(dir)
	require.NoError(t, err)
	require.Len(t, nodes, 1) // root "/"
	require.Contains(t, nodes, "/")
}

func TestWalkNonExistent(t *testing.T) {
	rule := &FilesystemRule{}
	_, err := rule.walk("/nonexistent/path")
	require.Error(t, err)
}

func TestVerifyIdentical(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	for _, dir := range []string{dir1, dir2} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("data"), 0644))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("more"), 0644))
	}

	rule := &FilesystemRule{}
	require.NoError(t, rule.verify(dir1, dir2))
}

func TestVerifyMissingInTarget(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "only-in-source.txt"), []byte("x"), 0644))

	rule := &FilesystemRule{}
	err := rule.verify(dir1, dir2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file not found in target image")
}

func TestVerifyExtraInTarget(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "only-in-target.txt"), []byte("x"), 0644))

	rule := &FilesystemRule{}
	err := rule.verify(dir1, dir2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file not found in source image")
}

func TestVerifyContentMismatch(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "file.txt"), []byte("aaa"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir2, "file.txt"), []byte("bbb"), 0644))

	rule := &FilesystemRule{}
	err := rule.verify(dir1, dir2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "file not match in target image")
}

func TestGetXattrs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "test")
	require.NoError(t, os.WriteFile(file, []byte("data"), 0644))

	attrs, err := getXattrs(file)
	require.NoError(t, err)
	require.NotNil(t, attrs)
	// Most test environments won't have xattrs set, so empty map is expected
	require.Empty(t, attrs)
}

func TestGetXattrsNonExistent(t *testing.T) {
	_, err := getXattrs("/nonexistent/path")
	require.Error(t, err)
}

func TestMountImageInvalid(t *testing.T) {
	rule := &FilesystemRule{}
	_, err := rule.mountImage(&Image{Parsed: &parser.Parsed{}}, "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid image for mounting")
}

func TestFilesystemRuleValidateSkip(t *testing.T) {
	rule := &FilesystemRule{
		SourceImage: &Image{Parsed: nil},
		TargetImage: &Image{Parsed: nil},
	}
	require.NoError(t, rule.Validate())
}
