package e2e

// Everything that decides the content of the cross-version compatibility
// images lives in this file: the corpus, the layouts, the build steps and the
// manifest the images are verified against. CI caches the images a released
// nydus builds keyed on this file, so a change here rebuilds them.

import (
	"archive/tar"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	// imagesManifestName is the file in the images directory that lists the
	// images and the trees they must reproduce.
	imagesManifestName = "manifest.json"

	// imagesManifestVersion guards against reading images built by a
	// different revision of this file.
	imagesManifestVersion = 1

	// corpusSeed seeds the generator every corpus draws its content from.
	corpusSeed = 20260930

	// maxFullHashSize bounds the files hashed in full. Larger files are
	// sparse and are verified by their data extents instead, so a mount does
	// not have to stream gigabytes of holes.
	maxFullHashSize = 64 << 20
)

// buildLayout is one `nydus build` configuration exercised by the check.
type buildLayout struct {
	// name is the name of the image and of its subtests.
	name string

	// native layouts (erofs-*) carry no blob meta and need no cache to mount.
	native bool

	// fromTar layouts stream-convert an OCI layer tarball of the corpus, as
	// nydusify does, instead of walking the directory.
	fromTar bool

	// args are the `nydus build` flags of the layout.
	args []string
}

// singleLayerLayouts are the layouts every single-layer image is built with.
var singleLayerLayouts = []buildLayout{
	{name: "zstd", args: []string{"--compressor", "zstd"}},
	{name: "zstd-4k", args: []string{"--compressor", "zstd", "--chunk-size", "4096"}},
	{name: "zstd-4k-group-64k", args: []string{"--compressor", "zstd", "--chunk-size", "4096", "--chunk-group-minimum-size", "65536"}},
	{name: "zstd-8m", args: []string{"--compressor", "zstd", "--chunk-size", "8388608"}},
	{name: "zstd-no-digest", args: []string{"--compressor", "zstd", "--digester", "none"}},
	{name: "lz4-64k", args: []string{"--compressor", "lz4", "--chunk-size", "65536"}},
	{name: "none-4k", args: []string{"--compressor", "none", "--chunk-size", "4096"}},
	{name: "erofs-none", native: true, args: []string{"--compressor", "erofs-none"}},
	{name: "erofs-none-64k-align-64k", native: true, args: []string{"--compressor", "erofs-none", "--chunk-size", "65536", "--erofs-data-alignment", "65536"}},
	{name: "erofs-lz4", native: true, args: []string{"--compressor", "erofs-lz4"}},
	{name: "erofs-zstd", native: true, args: []string{"--compressor", "erofs-zstd"}},
	{name: "tar-zstd", fromTar: true, args: []string{"--compressor", "zstd"}},
	{name: "tar-erofs-lz4", fromTar: true, native: true, args: []string{"--compressor", "erofs-lz4"}},
}

// mergeLayouts are the layer layouts merged into an overlaid bootstrap.
var mergeLayouts = []buildLayout{
	{name: "zstd-4k", args: []string{"--compressor", "zstd", "--chunk-size", "4096"}},
	{name: "erofs-lz4", native: true, args: []string{"--compressor", "erofs-lz4"}},
	{name: "tar-zstd", fromTar: true, args: []string{"--compressor", "zstd"}},
}

// imagesManifest describes the images in an images directory. Paths are
// relative to that directory, so it can be restored anywhere.
type imagesManifest struct {
	// Version is the imagesManifestVersion of the revision that wrote the
	// manifest.
	Version int `json:"version"`

	// Builder is the `nydus --version` of the binary that built the images.
	Builder string `json:"builder"`

	// Trees are the expected trees, by the name builtImage.Tree refers to.
	Trees map[string][]treeEntry `json:"trees"`

	// Images are the built images.
	Images []builtImage `json:"images"`
}

// builtImage is one built image and the tree it must reproduce.
type builtImage struct {
	// Name is the layout name, prefixed with merged- for a merged image.
	Name string `json:"name"`

	// Native marks an erofs-* layout, which has no chunk cache to exercise.
	Native bool `json:"native,omitempty"`

	// Merged marks a bootstrap merged from several layers.
	Merged bool `json:"merged,omitempty"`

	// Tree names the expected tree in imagesManifest.Trees.
	Tree string `json:"tree"`

	// Bootstrap is the path of the bootstrap.
	Bootstrap string `json:"bootstrap"`

	// BlobDir is the directory holding the blobs.
	BlobDir string `json:"blob_dir"`

	// Blobs are the full blobs, one per layer.
	Blobs []string `json:"blobs"`
}

// treeEntry is the state of one path of a tree: what the source holds and
// what every read path of the image must report back.
type treeEntry struct {
	// Path is the path relative to the root of the tree.
	Path byteString `json:"path"`

	// Type is dir, reg, symlink, chr, blk, fifo or socket.
	Type string `json:"type"`

	// Mode is the permission and special bits.
	Mode uint32 `json:"mode"`

	// UID is the owner.
	UID uint32 `json:"uid"`

	// GID is the group.
	GID uint32 `json:"gid"`

	// MtimeSec is the whole seconds of the modification time.
	MtimeSec int64 `json:"mtime_sec"`

	// MtimeNsec is the nanosecond part of the modification time.
	MtimeNsec int64 `json:"mtime_nsec"`

	// Size of regular files and symlinks.
	Size int64 `json:"size,omitempty"`

	// Nlink of non-directories.
	Nlink uint64 `json:"nlink,omitempty"`

	// Major is the device major number of chr and blk.
	Major uint32 `json:"major,omitempty"`

	// Minor is the device minor number of chr and blk.
	Minor uint32 `json:"minor,omitempty"`

	// Target is the symlink target.
	Target byteString `json:"target,omitempty"`

	// Link is the smallest path of the entry's hardlink group, if any.
	Link byteString `json:"link,omitempty"`

	// Xattrs are the extended attributes, less the trusted.nydus.* ones.
	Xattrs map[string]byteString `json:"xattrs,omitempty"`

	// SHA256 of the content of regular files up to maxFullHashSize.
	SHA256 string `json:"sha256,omitempty"`

	// Extents are the data of larger regular files; the rest reads as zeros.
	Extents []dataExtent `json:"extents,omitempty"`

	// inode identifies the entry's inode while a tree is scanned.
	inode string
}

// dataExtent is a data range of a large sparse file.
type dataExtent struct {
	// Offset is the start of the range.
	Offset int64 `json:"offset"`

	// Length is the length of the range.
	Length int64 `json:"length"`

	// SHA256 of the data in the range.
	SHA256 string `json:"sha256"`
}

// byteString is a byte string (a file name, link target or xattr value) that
// round-trips through JSON as a Go-quoted string, so names and values that are
// not valid UTF-8 survive.
type byteString string

// MarshalText returns the bytes as a Go-quoted string.
func (b byteString) MarshalText() ([]byte, error) {
	return []byte(strconv.Quote(string(b))), nil
}

// UnmarshalText sets the bytes from a Go-quoted string.
func (b *byteString) UnmarshalText(text []byte) error {
	s, err := strconv.Unquote(string(text))
	*b = byteString(s)
	return err
}

// buildImages stages the corpus and merge layers, builds every image
// into imagesDir with builder and writes the manifest the reader side checks them
// against.
func buildImages(t *testing.T, builder, imagesDir string) *imagesManifest {
	t.Helper()
	assert.NoError(t, os.RemoveAll(imagesDir))
	assert.NoError(t, os.MkdirAll(imagesDir, 0o755))
	workDir := t.TempDir()

	rel := func(path string) string {
		r, err := filepath.Rel(imagesDir, path)
		assert.NoError(t, err)
		return r
	}

	// Stage the corpus and the merge layers, and record the trees the images
	// must reproduce, once as walked and once as a layer tarball carries them.
	source := filepath.Join(workDir, "corpus")
	stageCorpus(t, source)
	corpusTree := scanSource(t, source)

	layerDirs := []string{
		filepath.Join(workDir, "layer1"),
		filepath.Join(workDir, "layer2"),
		filepath.Join(workDir, "layer3"),
	}
	stageMergeLayers(t, layerDirs)
	var layerTrees, layerTarTrees [][]treeEntry
	for _, layerDir := range layerDirs {
		layerTree := scanSource(t, layerDir)
		layerTrees = append(layerTrees, layerTree)
		layerTarTrees = append(layerTarTrees, tarSource(layerTree))
	}

	manifest := &imagesManifest{
		Version: imagesManifestVersion,
		Builder: nydusVersion(t, builder),
		Trees: map[string][]treeEntry{
			"corpus":     corpusTree,
			"corpus-tar": tarSource(corpusTree),
			"merged":     overlayLayers(layerTrees...),
			"merged-tar": overlayLayers(layerTarTrees...),
		},
	}

	// Build one image of the corpus per layout.
	for _, layout := range singleLayerLayouts {
		t.Run(layout.name, func(t *testing.T) {
			imageDir := filepath.Join(imagesDir, layout.name)
			blobDir := filepath.Join(imageDir, "blobs")
			bootstrap := filepath.Join(imageDir, "image.boot")
			blob := buildLayer(t, builder, blobDir, bootstrap, source, layout)

			image := builtImage{
				Name:      layout.name,
				Native:    layout.native,
				Tree:      "corpus",
				Bootstrap: rel(bootstrap),
				BlobDir:   rel(blobDir),
				Blobs:     []string{rel(blob)},
			}
			if layout.fromTar {
				image.Tree = "corpus-tar"
			}
			manifest.Images = append(manifest.Images, image)
		})
	}

	// Build the three layers per merge layout and merge their bootstraps.
	for _, layout := range mergeLayouts {
		name := "merged-" + layout.name
		t.Run(name, func(t *testing.T) {
			imageDir := filepath.Join(imagesDir, name)
			blobDir := filepath.Join(imageDir, "blobs")
			bootstrap := filepath.Join(imageDir, "merged.boot")

			image := builtImage{
				Name:      name,
				Native:    layout.native,
				Merged:    true,
				Tree:      "merged",
				Bootstrap: rel(bootstrap),
				BlobDir:   rel(blobDir),
			}
			if layout.fromTar {
				image.Tree = "merged-tar"
			}

			var blobs []string
			for i, layerDir := range layerDirs {
				layerBootstrap := filepath.Join(imageDir, fmt.Sprintf("layer%d.boot", i+1))
				blob := buildLayer(t, builder, blobDir, layerBootstrap, layerDir, layout)
				blobs = append(blobs, blob)
				image.Blobs = append(image.Blobs, rel(blob))
			}

			util.MergeBootstrap(t, builder, bootstrap, blobs...)
			manifest.Images = append(manifest.Images, image)
		})
	}

	// Write the manifest, unless a build failed and it would describe images
	// that are not there.
	if !assert.False(t, t.Failed(), "not writing a manifest for a failed build") {
		return nil
	}

	data, err := json.MarshalIndent(manifest, "", " ")
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(filepath.Join(imagesDir, imagesManifestName), data, 0o644))

	return manifest
}

// loadImagesManifest reads the manifest of an images directory.
func loadImagesManifest(t *testing.T, dir string) *imagesManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, imagesManifestName))
	assert.NoError(t, err)

	var manifest imagesManifest
	assert.NoError(t, json.Unmarshal(data, &manifest))
	assert.Equal(t, imagesManifestVersion, manifest.Version, "images were built by a different revision of the compatibility check")
	assert.NotEmpty(t, manifest.Images)

	return &manifest
}

// nydusVersion returns the `nydus --version` line of bin.
func nydusVersion(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "--version").CombinedOutput()
	assert.NoError(t, err, "%s --version: %s", bin, out)
	return strings.TrimSpace(string(out))
}

// buildLayer builds source into blobDir with bootstrap alongside and returns the
// path of the single new full blob, which must be named by its SHA256. A tar
// layout streams a tarball of source through stdin.
func buildLayer(t *testing.T, bin, blobDir, bootstrap, source string, layout buildLayout) string {
	t.Helper()
	assert.NoError(t, os.MkdirAll(blobDir, 0o755))
	before := util.ListFiles(t, blobDir)

	// Run the build, feeding a tar layout the tarball through a pipe.
	args := append([]string{"build", "--blob-dir", blobDir, "--bootstrap", bootstrap}, layout.args...)
	var out []byte
	var err error
	if layout.fromTar {
		pr, pw := io.Pipe()
		written := make(chan error, 1)
		go func() {
			err := writeLayerTar(t, pw, source)
			_ = pw.CloseWithError(err)
			written <- err
		}()

		cmd := exec.Command(bin, append(args, "--source-type", "tar", "/dev/stdin")...)
		cmd.Stdin = pr
		out, err = cmd.CombinedOutput()
		_ = pr.CloseWithError(io.ErrClosedPipe)

		if writeErr := <-written; err == nil && writeErr != nil {
			err = writeErr
		}
	} else {
		out, err = exec.Command(bin, append(args, source)...).CombinedOutput()
	}
	assert.NoError(t, err, "nydus %s %s failed: %s", strings.Join(args, " "), source, out)

	// The build must leave exactly one blob, named by its digest, and a blob
	// meta beside it unless the layout is native.
	blobs, blobMetas := util.NewBlobFiles(t, blobDir, before)
	if !assert.Len(t, blobs, 1, "expected exactly one new blob in %s", blobDir) {
		return ""
	}
	assert.Equal(t, filepath.Base(blobs[0]), util.Sha256File(t, blobs[0]), "blob must be named by its SHA256")
	if layout.native {
		assert.Empty(t, blobMetas, "native layers carry no blob meta")
	} else {
		assert.Equal(t, []string{blobs[0] + ".blob.meta"}, blobMetas)
	}

	return blobs[0]
}

// isTarSafe reports whether s can be carried in a PAX record through
// `nydus build --source-type tar`: the tar crate splits PAX records at
// newlines, so it rejects a record containing one.
func isTarSafe(s string) bool {
	return !strings.Contains(s, "\n")
}

// tarCarriesXattr reports whether writeLayerTar carries the xattr name=value.
// trusted.* is left out: the builder drops it from a layer tar as
// containerd's Apply does, while older releases keep it.
func tarCarriesXattr(name string, value byteString) bool {
	return !strings.HasPrefix(name, "trusted.") && isTarSafe(name) && isTarSafe(string(value))
}

// writeLayerTar writes the tree under root as an OCI layer tarball: PAX
// headers carrying xattrs and nanosecond mtimes, and hardlinks as link entries
// to the first path of the inode. It leaves out sockets, which tar cannot
// carry, what isTarSafe rejects and the xattrs tarCarriesXattr rejects.
func writeLayerTar(t *testing.T, w io.Writer, root string) error {
	t.Helper()
	tw := tar.NewWriter(w)
	firstPath := map[uint64]string{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}

		// Leave out what the tarball cannot carry.
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !isTarSafe(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		kind := stat.Mode & unix.S_IFMT
		if kind == unix.S_IFSOCK {
			return nil
		}
		var target string
		if kind == unix.S_IFLNK {
			if target, err = os.Readlink(path); err != nil {
				return err
			}
			if !isTarSafe(target) {
				return nil
			}
		}

		// Carry the metadata in a PAX header.
		hdr := &tar.Header{
			Name:    rel,
			Mode:    int64(stat.Mode & 0o7777),
			Uid:     int(stat.Uid),
			Gid:     int(stat.Gid),
			ModTime: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec),
			Format:  tar.FormatPAX,
		}
		for name, value := range listXattrs(t, path) {
			if !tarCarriesXattr(name, value) {
				continue
			}
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr."+name] = string(value)
		}

		// Every path of an inode after the firstPath is a link entry to it.
		if kind != unix.S_IFDIR && stat.Nlink > 1 {
			if target, ok := firstPath[stat.Ino]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = target
				return tw.WriteHeader(hdr)
			}
			firstPath[stat.Ino] = rel
		}

		switch kind {
		case unix.S_IFDIR:
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		case unix.S_IFREG:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = stat.Size
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(tw, f)
			return err
		case unix.S_IFLNK:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = target
		case unix.S_IFCHR, unix.S_IFBLK:
			hdr.Typeflag = tar.TypeChar
			if kind == unix.S_IFBLK {
				hdr.Typeflag = tar.TypeBlock
			}
			hdr.Devmajor = int64(unix.Major(stat.Rdev))
			hdr.Devminor = int64(unix.Minor(stat.Rdev))
		case unix.S_IFIFO:
			hdr.Typeflag = tar.TypeFifo
		default:
			return fmt.Errorf("%s: unsupported file type %o", rel, kind)
		}

		return tw.WriteHeader(hdr)
	})
	if err != nil {
		return err
	}

	return tw.Close()
}

// scanSource records the tree under root, including the data extents of
// the files too large to hash in full.
func scanSource(t *testing.T, root string) []treeEntry {
	t.Helper()
	entries := scanTree(t, root)

	for i := range entries {
		if entries[i].Type == "reg" && entries[i].SHA256 == "" {
			entries[i].Extents = dataExtents(t, filepath.Join(root, string(entries[i].Path)), entries[i].Size)
		}
	}

	return entries
}

// scanTree records every path under root, root itself aside: the root
// of an image is synthesized by the builder and carries its own xattrs.
func scanTree(t *testing.T, root string) []treeEntry {
	t.Helper()
	var entries []treeEntry
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry, err := scanPath(t, path, rel)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	assert.NoError(t, err, "scanning %s", root)

	assignLinks(entries)
	return entries
}

// scanPath records the state of path, known as rel in its tree, without
// following a symlink.
func scanPath(t *testing.T, path, rel string) (treeEntry, error) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return treeEntry{}, err
	}

	entry := treeEntry{
		Path:      byteString(rel),
		Mode:      stat.Mode & 0o7777,
		UID:       stat.Uid,
		GID:       stat.Gid,
		MtimeSec:  stat.Mtim.Sec,
		MtimeNsec: stat.Mtim.Nsec,
	}

	// Record what the type decides: the content hash of a regular file up to
	// maxFullHashSize, the target of a symlink and the numbers of a device.
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.Type = "dir"
	case unix.S_IFREG:
		entry.Type = "reg"
		entry.Size = stat.Size
		if stat.Size <= maxFullHashSize {
			f, err := os.Open(path)
			if err != nil {
				return treeEntry{}, err
			}
			defer func() { _ = f.Close() }()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return treeEntry{}, err
			}
			entry.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
	case unix.S_IFLNK:
		entry.Type = "symlink"
		entry.Size = stat.Size
		target, err := os.Readlink(path)
		if err != nil {
			return treeEntry{}, err
		}
		entry.Target = byteString(target)
	case unix.S_IFCHR, unix.S_IFBLK:
		entry.Type = "chr"
		if stat.Mode&unix.S_IFMT == unix.S_IFBLK {
			entry.Type = "blk"
		}
		entry.Major = unix.Major(stat.Rdev)
		entry.Minor = unix.Minor(stat.Rdev)
	case unix.S_IFIFO:
		entry.Type = "fifo"
	case unix.S_IFSOCK:
		entry.Type = "socket"
	default:
		return treeEntry{}, fmt.Errorf("%s: unsupported file type %o", rel, stat.Mode&unix.S_IFMT)
	}

	// Directories have no hardlink group.
	if entry.Type != "dir" {
		entry.Nlink = stat.Nlink
		entry.inode = fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}

	entry.Xattrs = listXattrs(t, path)

	return entry, nil
}

// listXattrs returns the xattrs of path without following symlinks, less
// the internal ones the builder adds for the runtime, nil when there are
// none.
func listXattrs(t *testing.T, path string) map[string]byteString {
	t.Helper()
	var xattrs map[string]byteString
	for _, name := range util.ListXattr(t, path) {
		if util.IsInternalXattr(name) {
			continue
		}
		if xattrs == nil {
			xattrs = map[string]byteString{}
		}
		xattrs[name] = byteString(util.GetXattr(t, path, name))
	}

	return xattrs
}

// assignLinks points every member of a hardlink group at the group's
// smallest path, which identifies the group the same way in every tree.
func assignLinks(entries []treeEntry) {
	groups := map[string][]int{}
	for i, entry := range entries {
		if entry.inode != "" {
			groups[entry.inode] = append(groups[entry.inode], i)
		}
	}

	for _, members := range groups {
		if len(members) < 2 {
			for _, i := range members {
				entries[i].Link = ""
			}
			continue
		}
		smallest := slices.MinFunc(members, func(a, b int) int { return cmp.Compare(entries[a].Path, entries[b].Path) })
		for _, i := range members {
			entries[i].Link = entries[smallest].Path
		}
	}
}

// regroupLinks recomputes Link after entries were dropped or replaced,
// using the group each entry was in.
func regroupLinks(entries []treeEntry) {
	for i := range entries {
		entries[i].inode = string(entries[i].Link)
	}

	assignLinks(entries)

	for i := range entries {
		entries[i].inode = ""
	}
}

// withoutSockets drops the sockets a tarball cannot carry.
func withoutSockets(entries []treeEntry) []treeEntry {
	out := slices.DeleteFunc(slices.Clone(entries), func(entry treeEntry) bool { return entry.Type == "socket" })
	regroupLinks(out)
	return out
}

// tarSource is the tree an image built from writeLayerTar's tarball of
// entries holds.
func tarSource(entries []treeEntry) []treeEntry {
	// Drop what writeLayerTar leaves out.
	var out []treeEntry
	for _, entry := range withoutSockets(entries) {
		if !isTarSafe(string(entry.Path)) || !isTarSafe(string(entry.Target)) {
			continue
		}

		xattrs := entry.Xattrs
		entry.Xattrs = nil
		for name, value := range xattrs {
			if tarCarriesXattr(name, value) {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]byteString{}
				}
				entry.Xattrs[name] = value
			}
		}

		out = append(out, entry)
	}
	regroupLinks(out)

	// A tarball's hardlinks are all the links an inode gets.
	linkCount := map[byteString]uint64{}
	for _, entry := range out {
		linkCount[entry.Link]++
	}

	for i := range out {
		if out[i].Type != "dir" {
			out[i].Nlink = 1
			if out[i].Link != "" {
				out[i].Nlink = linkCount[out[i].Link]
			}
		}
	}

	return out
}

// overlayLayers applies OCI layer semantics to the layer trees, lowest first:
// an opaque marker hides everything below in its directory, `.wh.<name>`
// removes <name> and its subtree from below, a non-directory replaces
// whatever is below, and directories merge with the upper metadata winning.
// Hardlink groups never span layers.
func overlayLayers(layers ...[]treeEntry) []treeEntry {
	const whiteoutPrefix = ".wh."
	const opaqueMarker = ".wh..wh..opq"

	splitPath := func(path byteString) (string, string) {
		p := string(path)
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			return p[:i], p[i+1:]
		}
		return "", p
	}

	merged := map[byteString]treeEntry{}
	removeBelow := func(dir string, self bool) {
		for path := range merged {
			p := string(path)
			if (self && p == dir) || strings.HasPrefix(p, dir+"/") || dir == "" {
				delete(merged, path)
			}
		}
	}

	// Apply a layer's whiteouts to what is below, then lay its entries over.
	for layer, entries := range layers {
		for _, entry := range entries {
			dir, name := splitPath(entry.Path)
			if name == opaqueMarker {
				removeBelow(dir, false)
			} else if target, ok := strings.CutPrefix(name, whiteoutPrefix); ok {
				if dir != "" {
					target = dir + "/" + target
				}
				removeBelow(target, true)
			}
		}

		for _, entry := range entries {
			if _, name := splitPath(entry.Path); strings.HasPrefix(name, whiteoutPrefix) {
				continue
			}
			if lower, ok := merged[entry.Path]; ok && lower.Type == "dir" && entry.Type != "dir" {
				removeBelow(string(entry.Path), false)
			}
			if entry.Link != "" {
				entry.Link = byteString(fmt.Sprintf("%d/%s", layer, entry.Link))
			}
			merged[entry.Path] = entry
		}
	}

	out := slices.SortedFunc(maps.Values(merged), func(a, b treeEntry) int { return cmp.Compare(a.Path, b.Path) })
	regroupLinks(out)

	return out
}

// dataExtents maps the data of a large sparse file: its non-zero 4KiB
// blocks, coalesced into extents and hashed. Everything else reads as zeros.
func dataExtents(t *testing.T, path string, size int64) []dataExtent {
	t.Helper()
	const block = 4096

	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Walk the data ranges the filesystem reports and keep the blocks in them
	// that are not zeros, coalescing neighbours.
	var extents []dataExtent
	buf := make([]byte, block)
	zero := make([]byte, block)
	for off := int64(0); off < size; {
		data, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) || !assert.NoError(t, err) {
			break
		}
		hole, err := unix.Seek(int(f.Fd()), data, unix.SEEK_HOLE)
		if !assert.NoError(t, err) {
			break
		}
		for pos := data &^ (block - 1); pos < hole; pos += block {
			n := min(int64(block), size-pos)
			_, err := f.ReadAt(buf[:n], pos)
			assert.NoError(t, err)
			if bytes.Equal(buf[:n], zero[:n]) {
				continue
			}
			if last := len(extents) - 1; last >= 0 && extents[last].Offset+extents[last].Length == pos {
				extents[last].Length += n
			} else {
				extents = append(extents, dataExtent{Offset: pos, Length: n})
			}
		}
		off = hole
	}

	// Hash each extent.
	for i := range extents {
		data := make([]byte, extents[i].Length)
		_, err := f.ReadAt(data, extents[i].Offset)
		assert.NoError(t, err)
		sum := sha256.Sum256(data)
		extents[i].SHA256 = hex.EncodeToString(sum[:])
	}

	assert.NotEmpty(t, extents, "%s: a large file needs data to locate", path)
	return extents
}

// seededCorpus stages a deterministic tree: content comes from a seeded
// generator and pinTimes pins the timestamps of every entry.
type seededCorpus struct {
	*corpus.Corpus

	// rng is the seeded generator the content is drawn from.
	rng *mathrand.Rand

	// times are the timestamps set explicitly, by relative path, which pinTimes
	// pins before the default ones.
	times map[string]unix.Timespec
}

// newSeededCorpus returns an empty corpus at dir whose content is drawn from
// seed.
func newSeededCorpus(t *testing.T, dir string, seed int64) *seededCorpus {
	return &seededCorpus{
		Corpus: corpus.NewCorpus(t, dir),
		rng:    mathrand.New(mathrand.NewSource(seed)),
		times:  map[string]unix.Timespec{},
	}
}

// textWords is the vocabulary text draws its words from.
var textWords = strings.Fields("nydus erofs chunk blob meta bootstrap layer image overlay " +
	"whiteout hole sparse inode xattr dirent symlink device fifo socket hardlink compact " +
	"extended superblock digest zstd lz4 prefetch cache fuse mount export registry")

// random returns n incompressible bytes.
func (c *seededCorpus) random(n int) []byte {
	b := make([]byte, n)
	_, _ = c.rng.Read(b)
	return b
}

// text returns n bytes of compressible, but not repetitive, text.
func (c *seededCorpus) text(n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(textWords[c.rng.Intn(len(textWords))])
		if c.rng.Intn(12) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}

	return b.Bytes()[:n]
}

// setTime records the timestamp pinTimes pins on name.
func (c *seededCorpus) setTime(name string, sec, nsec int64) {
	c.times[name] = unix.Timespec{Sec: sec, Nsec: nsec}
}

// lsetxattr sets the xattr key of name itself, where corpus.SetXattr follows
// a symlink.
func (c *seededCorpus) lsetxattr(t *testing.T, name, key string, value []byte) {
	assert.NoError(t, unix.Lsetxattr(filepath.Join(c.Dir, name), key, value, 0), "%s: %s", name, key)
}

// createSocket creates the socket node name with mknod, so it needs no listener and
// gets the mode of a regular node.
func (c *seededCorpus) createSocket(t *testing.T, name string) {
	path := filepath.Join(c.Dir, name)
	assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	assert.NoError(t, unix.Mknod(path, unix.S_IFSOCK|0o755, 0))
}

// pinTimes pins the timestamps of every entry: the explicit ones, then a
// default for the rest, which mostly carry whole seconds (a compact inode
// cannot hold nanoseconds of its own) with every fifth one extended by a
// nanosecond part. Hardlinks share their inode's timestamp.
func (c *seededCorpus) pinTimes(t *testing.T) {
	t.Helper()
	var paths []string
	assert.NoError(t, filepath.WalkDir(c.Dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == c.Dir {
			return err
		}
		rel, err := filepath.Rel(c.Dir, path)
		paths = append(paths, rel)
		return err
	}))

	// Set each inode once, so the first path to reach it wins.
	done := map[uint64]bool{}
	set := func(rel string, ts unix.Timespec) {
		path := filepath.Join(c.Dir, rel)
		var stat unix.Stat_t
		assert.NoError(t, unix.Lstat(path, &stat))
		if done[stat.Ino] {
			return
		}
		done[stat.Ino] = true
		assert.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW), rel)
	}

	for _, rel := range slices.Sorted(maps.Keys(c.times)) {
		set(rel, c.times[rel])
	}

	for i, rel := range paths {
		ts := unix.Timespec{Sec: 1_700_000_000 + int64(i)*61}
		if i%5 == 4 {
			ts.Nsec = int64(i) * 7_919_993 % 1_000_000_000
		}
		set(rel, ts)
	}
	set(".", unix.Timespec{Sec: 1_700_000_000})
}

// stageCorpus stages the tree every single-layer image is built from.
func stageCorpus(t *testing.T, dir string) {
	t.Helper()
	c := newSeededCorpus(t, dir, corpusSeed)
	stageFileData(t, c)
	stageSparseFiles(t, c)
	stageInodeMetadata(t, c)
	stageHardlinks(t, c)
	stageXattrs(t, c)
	stageFileNames(t, c)
	stageDirs(t, c)
	stageSymlinks(t, c)
	stageSpecialFiles(t, c)
	c.pinTimes(t)
}

// stageFileData covers file data: sizes against every block, pcluster and
// chunk boundary of the layouts, inline tails, content that compresses well,
// badly or to nothing, and content that deduplicates.
func stageFileData(t *testing.T, c *seededCorpus) {
	// Full, one byte short and one byte over the 4KiB block, the 64KiB
	// chunk and pcluster, and the 1MiB, 2MiB and 8MiB chunks.
	for i, size := range []int{
		0, 1, 2, 511, 512, 513, 4095, 4096, 4097, 8191, 8192, 8193, 12289,
		65535, 65536, 65537, 131073, 1<<20 - 1, 1 << 20, 1<<20 + 1,
		2<<20 - 1, 2 << 20, 2<<20 + 1, 8<<20 + 4097,
	} {
		name := fmt.Sprintf("data/size/%08d", size)
		if i%2 == 0 {
			c.CreateFile(t, name, c.random(size))
		} else {
			c.CreateFile(t, name, c.text(size))
		}
	}

	// Tails EROFS may keep inline behind the inode. Whether one fits
	// depends on the inode form (32-byte compact, 64-byte extended) and its
	// xattrs, so every size is staged in each form.
	for _, size := range []int{31, 32, 33, 2048, 4000, 4031, 4032, 4033, 4063, 4064, 4065, 4095, 4096 + 4031, 4096 + 4065} {
		c.CreateFile(t, fmt.Sprintf("data/inline/compact_%05d", size), c.random(size))
		extended := fmt.Sprintf("data/inline/extended_%05d", size)
		c.CreateFile(t, extended, c.random(size))
		c.Chown(t, extended, 70000, 70000)
		withXattr := fmt.Sprintf("data/inline/xattr_%05d", size)
		c.CreateFile(t, withXattr, c.random(size))
		c.SetXattr(t, withXattr, "user.inline", bytes.Repeat([]byte{'x'}, 200))
	}

	// Written zeros: whole chunks of them are stored as holes.
	for _, size := range []int{4095, 4096, 65537, 2<<20 + 1} {
		c.CreateFile(t, fmt.Sprintf("data/content/zeros_%08d", size), make([]byte, size))
	}

	// A chunk that is zero but for its first or last byte is data.
	for _, at := range []int{0, 4095, 4096, 65535, 2<<20 - 1, 2 << 20, 4<<20 + 2} {
		data := make([]byte, 4<<20+3)
		data[at] = 0xa5
		c.CreateFile(t, fmt.Sprintf("data/content/lone_byte_%08d", at), data)
	}

	// Content that compresses well, badly or to nothing.
	pattern := make([]byte, 3<<20+5)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	c.CreateFile(t, "data/content/pattern", pattern)
	c.CreateFile(t, "data/content/text", c.text(1<<20+17))
	c.CreateFile(t, "data/content/random", c.random(128<<10))

	barely := c.random(256 << 10)
	for i := 0; i < len(barely); i += 16 {
		barely[i] = 0
	}
	c.CreateFile(t, "data/content/barely_compressible", barely)

	// Zero blocks inside data chunks, so no chunk is a hole.
	mixed := make([]byte, 1<<20)
	for off := 0; off < len(mixed); off += 8192 {
		copy(mixed[off:off+4096], c.random(4096))
	}
	c.CreateFile(t, "data/content/mixed_blocks", mixed)

	// Content shared by several files, which chunk deduplication may fold.
	shared := c.random(2<<20 + 8193)
	c.CreateFile(t, "data/dedup/orig", shared)
	c.CreateFile(t, "data/dedup/copy", shared)
	c.CreateFile(t, "data/dedup/prefix", append(append([]byte{}, shared[:1<<20]...), c.random(1<<20+5)...))
	c.CreateFile(t, "data/dedup/suffix", append(c.random(64<<10), shared[64<<10:]...))
	c.CreateFile(t, "data/dedup/repeated", bytes.Repeat(c.random(64<<10), 24))

	small := c.text(5000)
	for i := range 8 {
		c.CreateFile(t, fmt.Sprintf("data/dedup/small_%d", i), small)
	}
}

// stageSparseFiles covers sparse files: holes that start, end and span each
// block, pcluster and chunk boundary, all-hole files, alternating runs, written
// zeros next to real holes, and files past 4GiB.
func stageSparseFiles(t *testing.T, c *seededCorpus) {
	const block = 4096
	const chunk = 2 << 20

	// Nothing but a size, including a partial last block or chunk.
	for _, size := range []int64{1, block - 1, block, block + 1, 65536, 65537, chunk, chunk + 1, 9 << 20} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/empty/%08d", size), size, nil)
	}

	// A leading hole, then 16 bytes of data ending the file, the data
	// starting just before, on and just after each boundary.
	for _, off := range []int64{1, block - 1, block, block + 1, 65535, 65536, 65537, 1<<20 - 8, 1 << 20, chunk - 1, chunk, chunk + 1, 3*chunk - 8} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/leading/%08d", off), off+16, map[int64][]byte{off: c.random(16)})
	}

	// Data from offset zero, then a trailing hole such as truncate leaves.
	for _, n := range []int{1, block - 1, block, block + 1, 65536, chunk - 1, chunk, chunk + 1} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/trailing/%08d", n), 6<<20, map[int64][]byte{0: c.random(n)})
	}

	// A dozen bytes straddling a boundary, holes on both sides.
	for _, at := range []int64{block, 2 * block, 65536, 1 << 20, chunk, 2 * chunk} {
		c.CreateSparseFile(t, fmt.Sprintf("holes/straddle/%08d", at), 3*chunk, map[int64][]byte{at - 6: c.random(12)})
	}

	// Holes of one block, one 64KiB unit and several chunks between data.
	c.CreateSparseFile(t, "holes/gap/one_block", 3*block, map[int64][]byte{
		0: c.random(block), 2 * block: c.random(block),
	})
	c.CreateSparseFile(t, "holes/gap/one_64k", 3*65536, map[int64][]byte{
		0: c.random(65536), 2 * 65536: c.random(65536),
	})
	c.CreateSparseFile(t, "holes/gap/chunks", 5*chunk+100, map[int64][]byte{
		0: c.random(block), 4 * chunk: c.random(block), 5 * chunk: c.random(100),
	})

	// A partial block of data at the end of the file, after a long hole.
	c.CreateSparseFile(t, "holes/gap/partial_tail", chunk+2*block+100, map[int64][]byte{
		chunk + 2*block: c.random(100),
	})

	// Alternating data and holes at block granularity in both phases (the
	// shape xfstests punch-alternating makes), per 64KiB, and per chunk.
	for phase := range int64(2) {
		writes := map[int64][]byte{}
		for b := range int64(128) {
			if b%2 == phase {
				writes[b*block] = c.random(block)
			}
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/alternating/block_%d", phase), 128*block, writes)
	}

	writes := map[int64][]byte{}
	for i := int64(0); i < 32; i += 2 {
		writes[i*65536] = c.text(65536)
	}
	c.CreateSparseFile(t, "holes/alternating/64k", 32*65536, writes)

	writes = map[int64][]byte{}
	for i := int64(0); i < 6; i += 2 {
		writes[i*chunk] = c.random(block)
		writes[(i+1)*chunk-block] = c.random(block)
	}
	c.CreateSparseFile(t, "holes/alternating/chunk", 6*chunk, writes)

	// Written zeros read the same as a hole.
	c.CreateFile(t, "holes/zeros/written", make([]byte, chunk+4097))
	c.CreateSparseFile(t, "holes/zeros/sparse", chunk+4097, nil)
	c.CreateSparseFile(t, "holes/zeros/written_chunk", 3*chunk, map[int64][]byte{
		0: c.random(16), chunk: make([]byte, chunk), 3*chunk - 16: c.random(16),
	})

	// Islands of random length at random distances.
	for i := range 8 {
		writes := map[int64][]byte{}
		off := int64(c.rng.Intn(3 * block))
		for range 6 {
			n := 1 + c.rng.Intn(20000)
			writes[off] = c.random(n)
			off += int64(n) + int64(1+c.rng.Intn(600000))
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/islands/%02d", i), off+int64(c.rng.Intn(block)), writes)
	}

	// Past 4GiB an inode needs the extended form for its 64-bit size and
	// file offsets pass 32 bits; u32::MAX is the largest compact size.
	const fourGiB = int64(1) << 32
	c.CreateSparseFile(t, "holes/huge/4g_minus_1", fourGiB-1, map[int64][]byte{
		0: c.random(16), fourGiB - 17: c.random(16),
	})
	c.CreateSparseFile(t, "holes/huge/4g_plus_4097", fourGiB+4097, map[int64][]byte{
		0: c.random(16), chunk - 8: c.random(16), fourGiB - 8: c.random(16), fourGiB + 4097 - 16: c.random(16),
	})
}

// stageInodeMetadata covers inode attributes: permission and special mode
// bits, owners either side of the 16-bit compact limit, and timestamps at the
// epoch, with nanoseconds, and past 2038 and 2106.
func stageInodeMetadata(t *testing.T, c *seededCorpus) {
	// Permission and special bits on files and directories.
	for _, mode := range []uint32{0, 0o1, 0o7, 0o70, 0o400, 0o444, 0o600, 0o640, 0o644, 0o664, 0o700, 0o711, 0o755, 0o777, 0o1000, 0o1777, 0o2000, 0o2755, 0o4000, 0o4755, 0o6755, 0o7777} {
		name := fmt.Sprintf("meta/mode/file_%04o", mode)
		c.CreateFile(t, name, []byte(name))
		c.Chmod(t, name, mode)
	}

	for _, mode := range []uint32{0, 0o500, 0o555, 0o700, 0o711, 0o755, 0o777, 0o1777, 0o2775, 0o3777, 0o7755} {
		name := fmt.Sprintf("meta/mode/dir_%04o", mode)
		c.CreateFile(t, name+"/inner", []byte(name))
		c.Chmod(t, name, mode)
	}

	// Owners either side of the 16-bit compact limit, on every inode form.
	for _, id := range [][2]int{
		{0, 0}, {1, 2}, {1000, 1000}, {65534, 65534}, {65535, 65535}, {65535, 65536},
		{65536, 65535}, {65536, 65536}, {100000, 200000}, {2147483647, 2147483647},
		{2147483648, 1}, {1, 2147483648}, {4294967294, 4294967294},
	} {
		name := fmt.Sprintf("meta/owner/file_%d_%d", id[0], id[1])
		c.CreateFile(t, name, []byte(name))
		c.Chown(t, name, id[0], id[1])
	}

	c.CreateFile(t, "meta/owner/dir_70000/inner", nil)
	c.Chown(t, "meta/owner/dir_70000", 70000, 70001)
	c.CreateSymlink(t, "meta/owner/symlink", "file_0_0")
	c.Chown(t, "meta/owner/symlink", 12345, 54321)

	// Timestamps at the epoch, with nanoseconds, and past 2038 and 2106.
	for i, ts := range [][2]int64{
		{0, 0}, {0, 1}, {1, 0}, {1, 999999999}, {1234567890, 0}, {1234567890, 123456789},
		{1<<31 - 1, 0}, {1 << 31, 0}, {1<<32 - 1, 0}, {1 << 32, 0}, {1<<32 + 1, 500000000},
		{1 << 33, 999999999},
	} {
		name := fmt.Sprintf("meta/mtime/file_%02d", i)
		c.CreateFile(t, name, []byte(name))
		c.setTime(name, ts[0], ts[1])
	}

	c.CreateFile(t, "meta/mtime/dir_nsec/inner", nil)
	c.setTime("meta/mtime/dir_nsec", 1600000000, 987654321)
	c.CreateDir(t, "meta/mtime/dir_future")
	c.setTime("meta/mtime/dir_future", 1<<33, 0)
	c.CreateSymlink(t, "meta/mtime/symlink_nsec", "file_00")
	c.setTime("meta/mtime/symlink_nsec", 1500000000, 1)
}

// stageHardlinks covers hardlink groups: within and across directories,
// large, of empty, sparse and attribute-laden files, and of every
// non-directory type.
func stageHardlinks(t *testing.T, c *seededCorpus) {
	c.CreateFile(t, "links/pair/a", c.text(3000))
	c.CreateHardlink(t, "links/pair/b", "links/pair/a")
	c.CreateFile(t, "links/cross/x/f", c.random(10000))
	c.CreateHardlink(t, "links/cross/y/f", "links/cross/x/f")
	c.CreateHardlink(t, "links/cross/z/deeper/f", "links/cross/x/f")

	c.CreateFile(t, "links/many/target", []byte("many"))
	for i := range 100 {
		c.CreateHardlink(t, fmt.Sprintf("links/many/l%03d", i), "links/many/target")
	}

	c.CreateFile(t, "links/empty/a", nil)
	c.CreateHardlink(t, "links/empty/b", "links/empty/a")
	c.CreateSparseFile(t, "links/sparse/a", 3<<20, map[int64][]byte{1 << 20: c.random(100)})
	c.CreateHardlink(t, "links/sparse/b", "links/sparse/a")
	c.CreateFile(t, "links/big/a", c.text(3<<20))
	c.CreateHardlink(t, "links/big/b", "links/big/a")

	c.CreateFile(t, "links/meta/a", c.random(5000))
	c.Chmod(t, "links/meta/a", 0o4750)
	c.Chown(t, "links/meta/a", 70000, 70001)
	c.SetXattr(t, "links/meta/a", "user.link", []byte("shared by the group"))
	c.setTime("links/meta/a", 1650000000, 424242424)
	c.CreateHardlink(t, "links/meta/b", "links/meta/a")
	c.CreateHardlink(t, "links/meta/c", "links/meta/a")

	c.CreateFIFO(t, "links/special/fifo_a")
	c.CreateHardlink(t, "links/special/fifo_b", "links/special/fifo_a")
	c.CreateCharDev(t, "links/special/chr_a", 10, 200)
	c.CreateHardlink(t, "links/special/chr_b", "links/special/chr_a")
	c.CreateBlockDev(t, "links/special/blk_a", 8, 16)
	c.CreateHardlink(t, "links/special/blk_b", "links/special/blk_a")
	c.createSocket(t, "links/special/sock_a")
	c.CreateHardlink(t, "links/special/sock_b", "links/special/sock_a")
	c.CreateSymlink(t, "links/special/symlink_a", "../pair/a")
	c.CreateHardlink(t, "links/special/symlink_b", "links/special/symlink_a")
}

// stageXattrs covers extended attributes: empty, binary and long
// values, long names, many per inode, identical ones shared across inodes,
// every name prefix EROFS indexes, and xattrs on every file type.
func stageXattrs(t *testing.T, c *seededCorpus) {
	c.CreateFile(t, "xattr/small", []byte("x"))
	c.SetXattr(t, "xattr/small", "user.a", []byte("1"))
	c.CreateFile(t, "xattr/empty_value", []byte("x"))
	c.lsetxattr(t, "xattr/empty_value", "user.empty", nil)

	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	c.CreateFile(t, "xattr/binary_value", []byte("x"))
	c.SetXattr(t, "xattr/binary_value", "user.binary", binary)

	c.CreateFile(t, "xattr/long_value", []byte("x"))
	c.SetXattr(t, "xattr/long_value", "user.long", c.text(3000))
	c.CreateFile(t, "xattr/long_name", []byte("x"))
	c.SetXattr(t, "xattr/long_name", "user."+corpus.LongName('n', 250), []byte("v"))

	c.CreateFile(t, "xattr/many", []byte("x"))
	for i := range 100 {
		c.SetXattr(t, "xattr/many", fmt.Sprintf("user.m%03d", i), c.random(1+i%8))
	}

	// Entries are padded to 4 bytes, so name and value lengths cover every
	// remainder.
	c.CreateFile(t, "xattr/alignment", []byte("x"))
	for n := 1; n <= 4; n++ {
		for v := 0; v <= 4; v++ {
			c.SetXattr(t, "xattr/alignment", fmt.Sprintf("user.%s%d", corpus.LongName('a', n), v), bytes.Repeat([]byte{'v'}, v))
		}
	}

	// Identical xattrs on many inodes, which EROFS may share.
	shared := c.text(600)
	for i := range 30 {
		name := fmt.Sprintf("xattr/shared/f%02d", i)
		c.CreateFile(t, name, []byte{byte(i)})
		c.SetXattr(t, name, "user.shared", shared)
		c.SetXattr(t, name, "user.common", []byte("c"))
		c.SetXattr(t, name, "user.own", []byte(name))
	}

	// Every name prefix EROFS indexes, including the system ones.
	c.CreateFile(t, "xattr/prefixes", []byte("x"))
	c.SetXattr(t, "xattr/prefixes", "user.p", []byte("user"))
	c.SetXattr(t, "xattr/prefixes", "trusted.p", []byte("trusted"))
	c.SetXattr(t, "xattr/prefixes", "security.p", []byte("security"))
	c.CreateFile(t, "xattr/selinux", []byte("x"))
	c.SetXattr(t, "xattr/selinux", "security.selinux", []byte("system_u:object_r:bin_t:s0\x00"))
	c.CreateFile(t, "xattr/capability", []byte("x"))
	c.Chmod(t, "xattr/capability", 0o755)
	c.SetFileCaps(t, "xattr/capability", 1<<13, 0)
	c.CreateFile(t, "xattr/acl", []byte("x"))
	c.SetACL(t, "xattr/acl", corpus.MinimalACL(1000), false)
	c.CreateFile(t, "xattr/acl_dir/inner", []byte("x"))
	c.SetACL(t, "xattr/acl_dir", corpus.MinimalACL(2000), false)
	c.SetACL(t, "xattr/acl_dir", corpus.MinimalACL(3000), true)

	// Every file type, through the namespaces each one accepts.
	c.CreateFile(t, "xattr/types/dir/inner", nil)
	c.SetXattr(t, "xattr/types/dir", "user.dir", []byte("dir"))
	c.SetXattr(t, "xattr/types/dir", "trusted.dir", []byte("dir"))
	c.CreateSymlink(t, "xattr/types/symlink", "../small")
	c.lsetxattr(t, "xattr/types/symlink", "trusted.symlink", []byte("symlink"))
	c.CreateFIFO(t, "xattr/types/fifo")
	c.lsetxattr(t, "xattr/types/fifo", "trusted.fifo", []byte("fifo"))
	c.CreateCharDev(t, "xattr/types/chr", 1, 5)
	c.lsetxattr(t, "xattr/types/chr", "trusted.chr", []byte("chr"))
	c.createSocket(t, "xattr/types/socket")
	c.lsetxattr(t, "xattr/types/socket", "trusted.socket", []byte("socket"))
}

// stageFileNames covers file names: every length up to 255 bytes, special
// characters, bytes that are not UTF-8, and names that sort as prefixes.
func stageFileNames(t *testing.T, c *seededCorpus) {
	for n := 1; n <= 255; n++ {
		c.CreateFile(t, "names/length/"+corpus.LongName('n', n), nil)
	}

	for i, name := range []string{
		" leading", "trailing ", "mid space", "tab\there", "new\nline", "quote'sq", `quote"dq`,
		`back\slash`, "star*", "question?", "brack[et]", "dollar$", "semi;colon", "pct%d",
		"colon:name", "utf8-中文", "utf8-🙂", "combining-e\u0301", ".hidden", "...", "..dots",
		"dot.", "-dash", "~tilde", "Case", "case", "CASE", "=eq", "#hash", "@at", "{brace}",
	} {
		c.CreateFile(t, "names/special/"+name, []byte{byte(i)})
	}

	for _, name := range []string{
		"latin1_caf\xe9", "cp1252_\x93quoted\x94", "gbk_\xd6\xd0\xce\xc4", "lone_surrogate_\xed\xa0\x80",
		"overlong_\xc0\xaf", "truncated_\xe4\xb8", "ctrl_\x01\x02\x1f\x7f", "\xff", "\xfe\xff",
		"collide_\xfe", "collide_\xff", "collide_\xfe\xfe",
	} {
		c.CreateFile(t, "names/raw/"+name, []byte(name))
	}

	for _, name := range []string{"pre", "pre0", "preA", "prea", "pre_", "pre~", "pre\x7f", "pre\x80", "pre\xff"} {
		c.CreateFile(t, "names/prefix/"+name, []byte(name))
	}
}

// stageDirs covers directories: empty, deeply nested, spanning many
// blocks with short, mixed and 255-byte names, entries that end exactly on,
// just short of and just past a 4KiB directory block, and one of each type.
func stageDirs(t *testing.T, c *seededCorpus) {
	c.CreateDir(t, "dirs/empty")
	c.CreateDir(t, "dirs/empty_chain/a/b/c/d")

	path := "dirs/deep"
	for depth := 1; depth <= 40; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
		c.CreateFile(t, path+"/leaf", []byte(path))
	}

	// Directories spanning many blocks, with short, mixed and 255-byte names.
	for i := range 1000 {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_short/%03d", i), nil)
	}
	for i := range 400 {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_mixed/%0*d", 1+i%255, i), nil)
	}
	for i := range 100 {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_long/%s%03d", corpus.LongName('l', 252), i), nil)
	}

	for i := range 300 {
		c.CreateDir(t, fmt.Sprintf("dirs/subdirs/s%03d", i))
	}

	// Each dirent is a 12-byte header plus its name, and "." and ".."
	// come first.
	const block, dirent, nameLen = 4096, 12, 30
	for _, delta := range []int{-1, 0, 1} {
		dir := fmt.Sprintf("dirs/packing/exact_%+d", delta)
		c.CreateDir(t, dir)
		used := 2*dirent + 1 + 2
		for i := 0; used+dirent+nameLen <= block+delta; i++ {
			c.CreateFile(t, fmt.Sprintf("%s/%s%04d", dir, corpus.LongName('p', nameLen-4), i), nil)
			used += dirent + nameLen
		}
	}

	c.CreateFile(t, "dirs/types/file", []byte("file"))
	c.CreateDir(t, "dirs/types/dir")
	c.CreateSymlink(t, "dirs/types/symlink", "file")
	c.CreateFIFO(t, "dirs/types/fifo")
	c.CreateCharDev(t, "dirs/types/chr", 1, 7)
	c.CreateBlockDev(t, "dirs/types/blk", 7, 0)
	c.createSocket(t, "dirs/types/socket")
}

// stageSymlinks covers symlink targets of every length class up to
// PATH_MAX, around the inline limits, and unusual targets.
func stageSymlinks(t *testing.T, c *seededCorpus) {
	for _, n := range []int{1, 2, 31, 32, 33, 255, 256, 1023, 1024, 2048, 4031, 4032, 4033, 4063, 4064, 4065, 4094, 4095} {
		c.CreateSymlink(t, fmt.Sprintf("symlinks/length_%04d", n), corpus.LongName('t', n))
	}

	for name, target := range map[string]string{
		"dangling": "missing/target",
		"absolute": "/etc/hostname",
		"dir":      "../dirs",
		"dot":      ".",
		"dotdot":   "..",
		"self":     "self",
		"raw":      "caf\xe9/\xff",
		"spaces":   "with space/and\nnewline",
		"chain_a":  "chain_b",
		"chain_b":  "chain_c",
		"chain_c":  "../data/size/00000001",
	} {
		c.CreateSymlink(t, "symlinks/"+name, target)
	}
}

// stageSpecialFiles covers device, fifo and socket nodes, with device
// numbers past 8 bits up to the 12-bit major and 20-bit minor limits.
func stageSpecialFiles(t *testing.T, c *seededCorpus) {
	c.CreateFIFO(t, "special/fifo")
	c.CreateFIFO(t, "special/fifo_0600")
	c.Chmod(t, "special/fifo_0600", 0o600)

	for _, dev := range [][2]uint32{{1, 3}, {4, 64}, {10, 200}, {136, 1}, {255, 255}, {256, 0}, {0, 256}, {259, 65536}, {4095, 1048575}} {
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%d_%d", dev[0], dev[1]), dev[0], dev[1])
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%d_%d", dev[0], dev[1]), dev[0], dev[1])
	}

	c.createSocket(t, "special/socket")
	c.createSocket(t, "special/socket_0700")
	c.Chmod(t, "special/socket_0700", 0o700)
}

// stageMergeLayers stages three layers whose overlay exercises every
// whiteout form, type changes in both directions, metadata overrides of files
// and directories, hardlink groups broken or removed by upper layers, and a
// name removed and re-added.
func stageMergeLayers(t *testing.T, layerDirs []string) {
	t.Helper()
	if !assert.Len(t, layerDirs, 3) {
		return
	}

	lower := newSeededCorpus(t, layerDirs[0], corpusSeed+1)
	shared := lower.random(3<<20 + 17)
	lower.CreateFile(t, "keep/text", lower.text(10000))
	lower.CreateFile(t, "keep/random", shared)
	lower.CreateSparseFile(t, "keep/sparse", 5<<20, map[int64][]byte{2<<20 - 8: lower.random(16)})
	lower.CreateFile(t, "keep/xattr", []byte("x"))
	lower.SetXattr(t, "keep/xattr", "user.layer", []byte("lower"))
	lower.CreateSymlink(t, "keep/symlink", "text")
	lower.CreateFIFO(t, "keep/fifo")
	lower.CreateCharDev(t, "keep/chr", 1, 3)
	lower.CreateFile(t, "keep/owner", nil)
	lower.Chown(t, "keep/owner", 70000, 70000)

	lower.CreateFile(t, "change/replaced", lower.text(5000))
	lower.CreateFile(t, "change/removed", []byte("removed"))
	lower.CreateFile(t, "change/removed_dir/a", nil)
	lower.CreateFile(t, "change/removed_dir/sub/b", nil)
	lower.CreateFile(t, "change/opaque/old", nil)
	lower.CreateFile(t, "change/opaque/old_sub/x", nil)
	lower.CreateFile(t, "change/file_to_dir", []byte("file"))
	lower.CreateFile(t, "change/dir_to_file/child", []byte("child"))
	lower.CreateFile(t, "change/file_to_symlink", []byte("file"))
	lower.CreateSymlink(t, "change/symlink_to_file", "replaced")
	lower.CreateFIFO(t, "change/fifo_to_file")
	lower.CreateFile(t, "change/readded", []byte("v1"))
	lower.CreateFile(t, "change/meta_file", []byte("lower"))
	lower.SetXattr(t, "change/meta_file", "user.a", []byte("lower"))
	lower.CreateFile(t, "change/meta_dir/lower_child", nil)
	lower.SetXattr(t, "change/meta_dir", "user.dir", []byte("lower"))
	lower.Chown(t, "change/meta_dir", 1000, 1000)

	lower.CreateFile(t, "links/a", lower.text(4000))
	lower.CreateHardlink(t, "links/b", "links/a")
	lower.CreateHardlink(t, "links/c", "links/a")
	lower.CreateFile(t, "links/p", lower.text(100))
	lower.CreateHardlink(t, "links/q", "links/p")
	lower.CreateFile(t, "links/whole/x", nil)
	lower.CreateHardlink(t, "links/whole/y", "links/whole/x")

	lower.pinTimes(t)

	middle := newSeededCorpus(t, layerDirs[1], corpusSeed+2)
	middle.CreateFile(t, "keep_copy/random", shared)

	middle.CreateFile(t, "change/.wh.removed", nil)
	middle.CreateFile(t, "change/.wh.removed_dir", nil)
	middle.CreateFile(t, "change/.wh.never_existed", nil)
	middle.CreateFile(t, "change/opaque/.wh..wh..opq", nil)
	middle.CreateFile(t, "change/opaque/new", []byte("new"))
	middle.CreateFile(t, "change/replaced", middle.random(70000))
	middle.Chmod(t, "change/replaced", 0o600)
	middle.CreateFile(t, "change/file_to_dir/inner", []byte("inner"))
	middle.CreateFile(t, "change/dir_to_file", []byte("now a file"))
	middle.CreateSymlink(t, "change/file_to_symlink", "replaced")
	middle.CreateFile(t, "change/symlink_to_file", []byte("now a file"))
	middle.CreateFile(t, "change/fifo_to_file", []byte("now a file"))
	middle.CreateFile(t, "change/.wh.readded", nil)
	middle.CreateFile(t, "change/meta_file", []byte("middle"))
	middle.SetXattr(t, "change/meta_file", "user.b", []byte("middle"))
	middle.CreateFile(t, "change/meta_dir/middle_child", nil)
	middle.SetXattr(t, "change/meta_dir", "user.dir", []byte("middle"))
	middle.Chown(t, "change/meta_dir", 2000, 2000)
	middle.Chmod(t, "change/meta_dir", 0o700)

	middle.CreateFile(t, "links/b", []byte("breaks the group"))
	middle.CreateFile(t, "links/.wh.q", nil)
	middle.CreateFile(t, "links/.wh.whole", nil)
	middle.CreateFile(t, "links/new_a", middle.text(300))
	middle.CreateHardlink(t, "links/new_b", "links/new_a")

	middle.pinTimes(t)

	upper := newSeededCorpus(t, layerDirs[2], corpusSeed+3)
	upper.CreateFile(t, "change/readded", []byte("v3"))
	upper.CreateFile(t, "change/.wh.file_to_dir", nil)
	upper.CreateFile(t, "change/opaque/.wh.new", nil)
	upper.CreateFile(t, "change/opaque/newest", nil)
	upper.CreateFile(t, "fresh/deep/er/file", upper.text(2000))

	upper.CreateDir(t, "change/meta_dir")
	upper.SetXattr(t, "change/meta_dir", "user.dir", []byte("upper"))
	upper.setTime("change/meta_dir", 1800000000, 123)

	upper.pinTimes(t)
}
