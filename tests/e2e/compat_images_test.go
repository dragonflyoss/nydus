package e2e

// Everything that decides the content of the cross-version compatibility
// images lives in this file: the corpus, the layouts, the build steps and the
// manifest the images are verified against. CI caches the images a released
// nydus builds keyed on this file, so a change here rebuilds them.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	// compatManifestName is the file in the images directory that lists the
	// images and the trees they must reproduce.
	compatManifestName = "manifest.json"
	// compatManifestVersion guards against reading images built by a
	// different revision of this file.
	compatManifestVersion = 1
	compatSeed            = 20260930
	// compatFullHashLimit bounds the files hashed in full. Larger files are
	// sparse and are verified by their data extents instead, so a mount does
	// not have to stream gigabytes of holes.
	compatFullHashLimit = 64 << 20
)

// compatLayout is one `nydus build` configuration exercised by the check.
type compatLayout struct {
	name string
	// native layouts (erofs-*) carry no blob meta and need no cache to mount.
	native bool
	// tar layouts stream-convert an OCI layer tarball of the corpus, as
	// nydusify does, instead of walking the directory.
	tar  bool
	args []string
}

var compatLayouts = []compatLayout{
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
	{name: "tar-zstd", tar: true, args: []string{"--compressor", "zstd"}},
	{name: "tar-erofs-lz4", tar: true, native: true, args: []string{"--compressor", "erofs-lz4"}},
}

// compatMergeLayouts are the layer layouts merged into an overlaid bootstrap.
var compatMergeLayouts = []compatLayout{
	{name: "zstd-4k", args: []string{"--compressor", "zstd", "--chunk-size", "4096"}},
	{name: "erofs-lz4", native: true, args: []string{"--compressor", "erofs-lz4"}},
	{name: "tar-zstd", tar: true, args: []string{"--compressor", "zstd"}},
}

// compatManifest describes the images in an images directory. Paths are
// relative to that directory, so it can be restored anywhere.
type compatManifest struct {
	Version int `json:"version"`
	// Builder is the `nydus --version` of the binary that built the images.
	Builder string                   `json:"builder"`
	Trees   map[string][]compatEntry `json:"trees"`
	Images  []compatImage            `json:"images"`
}

// compatImage is one built image and the tree it must reproduce.
type compatImage struct {
	Name   string `json:"name"`
	Native bool   `json:"native,omitempty"`
	Merged bool   `json:"merged,omitempty"`
	// Tree names the expected tree in compatManifest.Trees.
	Tree      string `json:"tree"`
	Bootstrap string `json:"bootstrap"`
	BlobDir   string `json:"blob_dir"`
	// Blobs are the full blobs, one per layer.
	Blobs []string `json:"blobs"`
}

// compatEntry is the state of one path of a tree: what the source holds and
// what every read path of the image must report back.
type compatEntry struct {
	Path      compatBytes `json:"path"`
	Type      string      `json:"type"`
	Mode      uint32      `json:"mode"`
	UID       uint32      `json:"uid"`
	GID       uint32      `json:"gid"`
	MtimeSec  int64       `json:"mtime_sec"`
	MtimeNsec int64       `json:"mtime_nsec"`
	// Size of regular files and symlinks.
	Size int64 `json:"size,omitempty"`
	// Nlink of non-directories.
	Nlink  uint64      `json:"nlink,omitempty"`
	Major  uint32      `json:"major,omitempty"`
	Minor  uint32      `json:"minor,omitempty"`
	Target compatBytes `json:"target,omitempty"`
	// Link is the smallest path of the entry's hardlink group, if any.
	Link   compatBytes            `json:"link,omitempty"`
	Xattrs map[string]compatBytes `json:"xattrs,omitempty"`
	// SHA256 of the content of regular files up to compatFullHashLimit.
	SHA256 string `json:"sha256,omitempty"`
	// Extents are the data of larger regular files; the rest reads as zeros.
	Extents []compatExtent `json:"extents,omitempty"`

	// inode identifies the entry's inode while a tree is scanned.
	inode string
}

// compatExtent is a data range of a large sparse file.
type compatExtent struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// compatBytes is a byte string (a file name, link target or xattr value) that
// round-trips through JSON as a Go-quoted string, so names and values that are
// not valid UTF-8 survive.
type compatBytes string

func (b compatBytes) MarshalText() ([]byte, error) {
	return []byte(strconv.Quote(string(b))), nil
}

func (b *compatBytes) UnmarshalText(text []byte) error {
	s, err := strconv.Unquote(string(text))
	*b = compatBytes(s)
	return err
}

// compatBuildImages stages the corpus and merge layers, builds every image
// into out with builder and writes the manifest the reader side checks them
// against.
func compatBuildImages(t *testing.T, builder, out string) *compatManifest {
	t.Helper()
	require.NoError(t, os.RemoveAll(out))
	require.NoError(t, os.MkdirAll(out, 0755))
	work := t.TempDir()
	rel := func(path string) string {
		r, err := filepath.Rel(out, path)
		require.NoError(t, err)
		return r
	}

	src := filepath.Join(work, "corpus")
	compatMakeCorpus(t, src)
	tree := compatScanSource(t, src)

	layerDirs := []string{
		filepath.Join(work, "layer1"),
		filepath.Join(work, "layer2"),
		filepath.Join(work, "layer3"),
	}
	compatMakeMergeLayers(t, layerDirs)
	var layerTrees, layerTarTrees [][]compatEntry
	for _, dir := range layerDirs {
		layerTree := compatScanSource(t, dir)
		layerTrees = append(layerTrees, layerTree)
		layerTarTrees = append(layerTarTrees, compatTarSource(layerTree))
	}

	manifest := &compatManifest{
		Version: compatManifestVersion,
		Builder: compatVersion(t, builder),
		Trees: map[string][]compatEntry{
			"corpus":     tree,
			"corpus-tar": compatTarSource(tree),
			"merged":     compatOverlay(layerTrees...),
			"merged-tar": compatOverlay(layerTarTrees...),
		},
	}

	for _, layout := range compatLayouts {
		layout := layout
		t.Run(layout.name, func(t *testing.T) {
			dir := filepath.Join(out, layout.name)
			blobDir := filepath.Join(dir, "blobs")
			bootstrap := filepath.Join(dir, "image.bootstrap")
			blob := compatBuild(t, builder, blobDir, bootstrap, src, layout)
			image := compatImage{
				Name:      layout.name,
				Native:    layout.native,
				Tree:      "corpus",
				Bootstrap: rel(bootstrap),
				BlobDir:   rel(blobDir),
				Blobs:     []string{rel(blob)},
			}
			if layout.tar {
				image.Tree = "corpus-tar"
			}
			manifest.Images = append(manifest.Images, image)
		})
	}

	for _, layout := range compatMergeLayouts {
		layout := layout
		name := "merged-" + layout.name
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(out, name)
			blobDir := filepath.Join(dir, "blobs")
			bootstrap := filepath.Join(dir, "merged.bootstrap")
			image := compatImage{
				Name:      name,
				Native:    layout.native,
				Merged:    true,
				Tree:      "merged",
				Bootstrap: rel(bootstrap),
				BlobDir:   rel(blobDir),
			}
			if layout.tar {
				image.Tree = "merged-tar"
			}
			var blobs []string
			for i, layerDir := range layerDirs {
				layerBootstrap := filepath.Join(dir, fmt.Sprintf("layer%d.bootstrap", i+1))
				blob := compatBuild(t, builder, blobDir, layerBootstrap, layerDir, layout)
				blobs = append(blobs, blob)
				image.Blobs = append(image.Blobs, rel(blob))
			}
			compatRun(t, builder, append([]string{"merge", "--bootstrap", bootstrap}, blobs...)...)
			manifest.Images = append(manifest.Images, image)
		})
	}

	require.False(t, t.Failed(), "not writing a manifest for a failed build")
	data, err := json.MarshalIndent(manifest, "", " ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(out, compatManifestName), data, 0644))
	return manifest
}

// compatLoadManifest reads the manifest of an images directory.
func compatLoadManifest(t *testing.T, dir string) *compatManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, compatManifestName))
	require.NoError(t, err)
	var manifest compatManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, compatManifestVersion, manifest.Version, "images were built by a different revision of the compatibility check")
	require.NotEmpty(t, manifest.Images)
	return &manifest
}

// compatVersion returns the `nydus --version` line of bin.
func compatVersion(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "--version").CombinedOutput()
	require.NoError(t, err, "%s --version: %s", bin, out)
	return strings.TrimSpace(string(out))
}

// compatRun runs bin with args, failing the test with its output on error.
func compatRun(t *testing.T, bin string, args ...string) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	require.NoError(t, err, "nydus %s failed: %s", strings.Join(args, " "), out)
	t.Logf("nydus %s:\n%s", strings.Join(args, " "), out)
}

// compatBuild builds src into blobDir with bootstrap alongside and returns the
// path of the single new full blob, which must be named by its SHA256. A tar
// layout streams a tarball of src through stdin.
func compatBuild(t *testing.T, bin, blobDir, bootstrap, src string, layout compatLayout) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(blobDir, 0755))
	before := listFilesInDir(t, blobDir)

	args := append([]string{"build", "--blob-dir", blobDir, "--bootstrap", bootstrap}, layout.args...)
	var out []byte
	var err error
	if layout.tar {
		pr, pw := io.Pipe()
		written := make(chan error, 1)
		go func() {
			err := compatWriteTar(pw, src)
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
		out, err = exec.Command(bin, append(args, src)...).CombinedOutput()
	}
	require.NoError(t, err, "nydus %s %s failed: %s", strings.Join(args, " "), src, out)

	var blobs, metas []string
	for path := range listFilesInDir(t, blobDir) {
		if _, existed := before[path]; existed {
			continue
		}
		switch base := filepath.Base(path); {
		case sha256FilenamePattern.MatchString(base):
			blobs = append(blobs, path)
		case blobMetaFilenamePattern.MatchString(base):
			metas = append(metas, path)
		default:
			require.Failf(t, "unexpected build output", "%s", path)
		}
	}
	require.Len(t, blobs, 1, "expected exactly one new blob in %s", blobDir)
	require.Equal(t, filepath.Base(blobs[0]), sha256File(t, blobs[0]), "blob must be named by its SHA256")
	if layout.native {
		require.Empty(t, metas, "native layers carry no blob meta")
	} else {
		require.Equal(t, []string{blobs[0] + ".blob.meta"}, metas)
	}
	return blobs[0]
}

// compatTarSafe reports whether s can be carried in a PAX record through
// `nydus build --source-type tar`: the tar crate splits PAX records at
// newlines, so it rejects a record containing one.
func compatTarSafe(s string) bool {
	return !strings.Contains(s, "\n")
}

// compatWriteTar writes the tree under root as an OCI layer tarball: PAX
// headers carrying xattrs and nanosecond mtimes, and hardlinks as link entries
// to the first path of the inode. It leaves out sockets, which tar cannot
// carry, and what compatTarSafe rejects.
func compatWriteTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	first := map[uint64]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !compatTarSafe(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		kind := st.Mode & unix.S_IFMT
		if kind == unix.S_IFSOCK {
			return nil
		}
		var target string
		if kind == unix.S_IFLNK {
			if target, err = os.Readlink(path); err != nil {
				return err
			}
			if !compatTarSafe(target) {
				return nil
			}
		}

		hdr := &tar.Header{
			Name:    rel,
			Mode:    int64(st.Mode & 07777),
			Uid:     int(st.Uid),
			Gid:     int(st.Gid),
			ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
			Format:  tar.FormatPAX,
		}
		xattrs, err := compatListXattrs(path)
		if err != nil {
			return err
		}
		for name, value := range xattrs {
			if !compatTarSafe(name) || !compatTarSafe(string(value)) {
				continue
			}
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr."+name] = string(value)
		}

		if kind != unix.S_IFDIR && st.Nlink > 1 {
			if target, ok := first[st.Ino]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = target
				return tw.WriteHeader(hdr)
			}
			first[st.Ino] = rel
		}

		switch kind {
		case unix.S_IFDIR:
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		case unix.S_IFREG:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = st.Size
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
			hdr.Devmajor = int64(unix.Major(st.Rdev))
			hdr.Devminor = int64(unix.Minor(st.Rdev))
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

// compatScanSource records the tree under root, including the data extents of
// the files too large to hash in full.
func compatScanSource(t *testing.T, root string) []compatEntry {
	t.Helper()
	entries := compatScanTree(t, root)
	for i := range entries {
		if entries[i].Type == "reg" && entries[i].SHA256 == "" {
			entries[i].Extents = compatDataExtents(t, filepath.Join(root, string(entries[i].Path)), entries[i].Size)
		}
	}
	return entries
}

// compatScanTree records every path under root, root itself aside: the root
// of an image is synthesized by the builder and carries its own xattrs.
func compatScanTree(t *testing.T, root string) []compatEntry {
	t.Helper()
	var entries []compatEntry
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry, err := compatScanPath(path, rel)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	require.NoError(t, err, "scanning %s", root)
	compatAssignLinks(entries)
	return entries
}

func compatScanPath(path, rel string) (compatEntry, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return compatEntry{}, err
	}
	entry := compatEntry{
		Path:      compatBytes(rel),
		Mode:      st.Mode & 07777,
		UID:       st.Uid,
		GID:       st.Gid,
		MtimeSec:  st.Mtim.Sec,
		MtimeNsec: st.Mtim.Nsec,
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.Type = "dir"
	case unix.S_IFREG:
		entry.Type = "reg"
		entry.Size = st.Size
		if st.Size <= compatFullHashLimit {
			sum, err := compatHashFile(path)
			if err != nil {
				return compatEntry{}, err
			}
			entry.SHA256 = sum
		}
	case unix.S_IFLNK:
		entry.Type = "symlink"
		entry.Size = st.Size
		target, err := os.Readlink(path)
		if err != nil {
			return compatEntry{}, err
		}
		entry.Target = compatBytes(target)
	case unix.S_IFCHR, unix.S_IFBLK:
		entry.Type = "chr"
		if st.Mode&unix.S_IFMT == unix.S_IFBLK {
			entry.Type = "blk"
		}
		entry.Major = unix.Major(st.Rdev)
		entry.Minor = unix.Minor(st.Rdev)
	case unix.S_IFIFO:
		entry.Type = "fifo"
	case unix.S_IFSOCK:
		entry.Type = "socket"
	default:
		return compatEntry{}, fmt.Errorf("%s: unsupported file type %o", rel, st.Mode&unix.S_IFMT)
	}
	if entry.Type != "dir" {
		entry.Nlink = st.Nlink
		entry.inode = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	xattrs, err := compatListXattrs(path)
	if err != nil {
		return compatEntry{}, fmt.Errorf("%s: %w", rel, err)
	}
	entry.Xattrs = xattrs
	return entry, nil
}

func compatHashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// compatListXattrs returns the xattrs of path without following symlinks,
// less the trusted.nydus.* ones the builder adds for the runtime.
func compatListXattrs(path string) (map[string]compatBytes, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil || size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}
	var xattrs map[string]compatBytes
	for _, name := range strings.Split(string(buf[:n]), "\x00") {
		if name == "" || strings.HasPrefix(name, "trusted.nydus.") {
			continue
		}
		size, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, fmt.Errorf("getxattr %s: %w", name, err)
		}
		value := make([]byte, size)
		if size > 0 {
			if size, err = unix.Lgetxattr(path, name, value); err != nil {
				return nil, fmt.Errorf("getxattr %s: %w", name, err)
			}
		}
		if xattrs == nil {
			xattrs = map[string]compatBytes{}
		}
		xattrs[name] = compatBytes(value[:size])
	}
	return xattrs, nil
}

// compatAssignLinks points every member of a hardlink group at the group's
// smallest path, which identifies the group the same way in every tree.
func compatAssignLinks(entries []compatEntry) {
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
		link := entries[members[0]].Path
		for _, i := range members {
			if entries[i].Path < link {
				link = entries[i].Path
			}
		}
		for _, i := range members {
			entries[i].Link = link
		}
	}
}

// compatRegroupLinks recomputes Link after entries were dropped or replaced,
// using the group each entry was in (keyed by prefix, e.g. its layer).
func compatRegroupLinks(entries []compatEntry, prefix func(compatEntry) string) {
	for i := range entries {
		entries[i].inode = ""
		if entries[i].Link != "" {
			entries[i].inode = prefix(entries[i]) + string(entries[i].Link)
		}
	}
	compatAssignLinks(entries)
	for i := range entries {
		entries[i].inode = ""
	}
}

// compatWithoutSockets drops the sockets a tarball cannot carry.
func compatWithoutSockets(entries []compatEntry) []compatEntry {
	var out []compatEntry
	for _, entry := range entries {
		if entry.Type != "socket" {
			out = append(out, entry)
		}
	}
	compatRegroupLinks(out, func(compatEntry) string { return "" })
	return out
}

// compatTarSource is the tree an image built from compatWriteTar's tarball of
// entries holds.
func compatTarSource(entries []compatEntry) []compatEntry {
	var out []compatEntry
	for _, entry := range compatWithoutSockets(entries) {
		if !compatTarSafe(string(entry.Path)) || !compatTarSafe(string(entry.Target)) {
			continue
		}
		xattrs := entry.Xattrs
		entry.Xattrs = nil
		for name, value := range xattrs {
			if compatTarSafe(name) && compatTarSafe(string(value)) {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]compatBytes{}
				}
				entry.Xattrs[name] = value
			}
		}
		out = append(out, entry)
	}
	compatRegroupLinks(out, func(compatEntry) string { return "" })
	// A tarball's hardlinks are all the links an inode gets.
	members := map[compatBytes]uint64{}
	for _, entry := range out {
		members[entry.Link]++
	}
	for i := range out {
		if out[i].Type != "dir" {
			out[i].Nlink = 1
			if out[i].Link != "" {
				out[i].Nlink = members[out[i].Link]
			}
		}
	}
	return out
}

// compatOverlay applies OCI layer semantics to the layer trees, lowest first:
// an opaque marker hides everything below in its directory, `.wh.<name>`
// removes <name> and its subtree from below, a non-directory replaces
// whatever is below, and directories merge with the upper metadata winning.
// Hardlink groups never span layers.
func compatOverlay(layers ...[]compatEntry) []compatEntry {
	const whiteoutPrefix = ".wh."
	const opaqueMarker = ".wh..wh..opq"
	split := func(path compatBytes) (string, string) {
		p := string(path)
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			return p[:i], p[i+1:]
		}
		return "", p
	}
	merged := map[compatBytes]compatEntry{}
	removeBelow := func(dir string, self bool) {
		for path := range merged {
			p := string(path)
			if (self && p == dir) || strings.HasPrefix(p, dir+"/") || dir == "" {
				delete(merged, path)
			}
		}
	}

	for layer, entries := range layers {
		for _, entry := range entries {
			dir, name := split(entry.Path)
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
			if _, name := split(entry.Path); strings.HasPrefix(name, whiteoutPrefix) {
				continue
			}
			if lower, ok := merged[entry.Path]; ok && lower.Type == "dir" && entry.Type != "dir" {
				removeBelow(string(entry.Path), false)
			}
			if entry.Link != "" {
				entry.Link = compatBytes(fmt.Sprintf("%d/%s", layer, entry.Link))
			}
			merged[entry.Path] = entry
		}
	}

	out := make([]compatEntry, 0, len(merged))
	for _, entry := range merged {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	compatRegroupLinks(out, func(compatEntry) string { return "" })
	return out
}

// compatDataExtents maps the data of a large sparse file: its non-zero 4KiB
// blocks, coalesced into extents and hashed. Everything else reads as zeros.
func compatDataExtents(t *testing.T, path string, size int64) []compatExtent {
	t.Helper()
	const block = 4096
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	var extents []compatExtent
	buf := make([]byte, block)
	zero := make([]byte, block)
	for off := int64(0); off < size; {
		data, err := unix.Seek(int(f.Fd()), off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		require.NoError(t, err)
		hole, err := unix.Seek(int(f.Fd()), data, unix.SEEK_HOLE)
		require.NoError(t, err)
		for pos := data &^ (block - 1); pos < hole; pos += block {
			n := min(int64(block), size-pos)
			_, err := f.ReadAt(buf[:n], pos)
			require.NoError(t, err)
			if bytes.Equal(buf[:n], zero[:n]) {
				continue
			}
			if last := len(extents) - 1; last >= 0 && extents[last].Offset+extents[last].Length == pos {
				extents[last].Length += n
			} else {
				extents = append(extents, compatExtent{Offset: pos, Length: n})
			}
		}
		off = hole
	}

	for i := range extents {
		data := make([]byte, extents[i].Length)
		_, err := f.ReadAt(data, extents[i].Offset)
		require.NoError(t, err)
		sum := sha256.Sum256(data)
		extents[i].SHA256 = hex.EncodeToString(sum[:])
	}
	require.NotEmpty(t, extents, "%s: a large file needs data to locate", path)
	return extents
}

// compatCorpus stages a deterministic tree: content comes from a seeded
// generator and finish pins the timestamps of every entry.
type compatCorpus struct {
	*corpus.Corpus
	rng   *mathrand.Rand
	times map[string]unix.Timespec
}

func newCompatCorpus(t *testing.T, dir string, seed int64) *compatCorpus {
	return &compatCorpus{
		Corpus: corpus.NewCorpus(t, dir),
		rng:    mathrand.New(mathrand.NewSource(seed)),
		times:  map[string]unix.Timespec{},
	}
}

var compatWords = strings.Fields("nydus erofs chunk blob meta bootstrap layer image overlay " +
	"whiteout hole sparse inode xattr dirent symlink device fifo socket hardlink compact " +
	"extended superblock digest zstd lz4 prefetch cache fuse mount export registry")

// random returns n incompressible bytes.
func (c *compatCorpus) random(n int) []byte {
	b := make([]byte, n)
	_, _ = c.rng.Read(b)
	return b
}

// text returns n bytes of compressible, but not repetitive, text.
func (c *compatCorpus) text(n int) []byte {
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(compatWords[c.rng.Intn(len(compatWords))])
		if c.rng.Intn(12) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	return b.Bytes()[:n]
}

func (c *compatCorpus) setTime(name string, sec, nsec int64) {
	c.times[name] = unix.Timespec{Sec: sec, Nsec: nsec}
}

func (c *compatCorpus) lsetxattr(t *testing.T, name, key string, value []byte) {
	require.NoError(t, unix.Lsetxattr(filepath.Join(c.Dir, name), key, value, 0), "%s: %s", name, key)
}

func (c *compatCorpus) socket(t *testing.T, name string) {
	path := filepath.Join(c.Dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, unix.Mknod(path, unix.S_IFSOCK|0755, 0))
}

// finish pins the timestamps of every entry: the explicit ones, then a
// default for the rest, which mostly carry whole seconds (a compact inode
// cannot hold nanoseconds of its own) with every fifth one extended by a
// nanosecond part. Hardlinks share their inode's timestamp.
func (c *compatCorpus) finish(t *testing.T) {
	t.Helper()
	var paths []string
	require.NoError(t, filepath.WalkDir(c.Dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == c.Dir {
			return err
		}
		rel, err := filepath.Rel(c.Dir, path)
		paths = append(paths, rel)
		return err
	}))

	done := map[uint64]bool{}
	set := func(rel string, ts unix.Timespec) {
		path := filepath.Join(c.Dir, rel)
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(path, &st))
		if done[st.Ino] {
			return
		}
		done[st.Ino] = true
		require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW), rel)
	}
	explicit := make([]string, 0, len(c.times))
	for rel := range c.times {
		explicit = append(explicit, rel)
	}
	sort.Strings(explicit)
	for _, rel := range explicit {
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

// compatMakeCorpus stages the tree every single-layer image is built from.
func compatMakeCorpus(t *testing.T, dir string) {
	t.Helper()
	c := newCompatCorpus(t, dir, compatSeed)
	compatCorpusData(t, c)
	compatCorpusHoles(t, c)
	compatCorpusMetadata(t, c)
	compatCorpusLinks(t, c)
	compatCorpusXattrs(t, c)
	compatCorpusNames(t, c)
	compatCorpusDirs(t, c)
	compatCorpusSymlinks(t, c)
	compatCorpusSpecial(t, c)
	c.finish(t)
}

// compatCorpusData covers file data: sizes against every block, pcluster and
// chunk boundary of the layouts, inline tails, content that compresses well,
// badly or to nothing, and content that deduplicates.
func compatCorpusData(t *testing.T, c *compatCorpus) {
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

	shared := c.random(2<<20 + 8193)
	c.CreateFile(t, "data/dedup/orig", shared)
	c.CreateFile(t, "data/dedup/copy", shared)
	c.CreateFile(t, "data/dedup/prefix", append(append([]byte{}, shared[:1<<20]...), c.random(1<<20+5)...))
	c.CreateFile(t, "data/dedup/suffix", append(c.random(64<<10), shared[64<<10:]...))
	c.CreateFile(t, "data/dedup/repeated", bytes.Repeat(c.random(64<<10), 24))
	small := c.text(5000)
	for i := 0; i < 8; i++ {
		c.CreateFile(t, fmt.Sprintf("data/dedup/small_%d", i), small)
	}
}

// compatCorpusHoles covers sparse files: holes that start, end and span each
// block, pcluster and chunk boundary, all-hole files, alternating runs, written
// zeros next to real holes, and files past 4GiB.
func compatCorpusHoles(t *testing.T, c *compatCorpus) {
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
	for phase := int64(0); phase < 2; phase++ {
		writes := map[int64][]byte{}
		for b := int64(0); b < 128; b++ {
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
	for i := 0; i < 8; i++ {
		writes := map[int64][]byte{}
		off := int64(c.rng.Intn(3 * block))
		for j := 0; j < 6; j++ {
			n := 1 + c.rng.Intn(20000)
			writes[off] = c.random(n)
			off += int64(n) + int64(1+c.rng.Intn(600000))
		}
		c.CreateSparseFile(t, fmt.Sprintf("holes/islands/%02d", i), off+int64(c.rng.Intn(block)), writes)
	}
	// Past 4GiB an inode needs the extended form for its 64-bit size and
	// file offsets pass 32 bits; u32::MAX is the largest compact size.
	const g4 = int64(1) << 32
	c.CreateSparseFile(t, "holes/huge/4g_minus_1", g4-1, map[int64][]byte{
		0: c.random(16), g4 - 17: c.random(16),
	})
	c.CreateSparseFile(t, "holes/huge/4g_plus_4097", g4+4097, map[int64][]byte{
		0: c.random(16), chunk - 8: c.random(16), g4 - 8: c.random(16), g4 + 4097 - 16: c.random(16),
	})
}

// compatCorpusMetadata covers inode attributes: permission and special mode
// bits, owners either side of the 16-bit compact limit, and timestamps at the
// epoch, with nanoseconds, and past 2038 and 2106.
func compatCorpusMetadata(t *testing.T, c *compatCorpus) {
	for _, mode := range []uint32{0, 01, 07, 070, 0400, 0444, 0600, 0640, 0644, 0664, 0700, 0711, 0755, 0777, 01000, 01777, 02000, 02755, 04000, 04755, 06755, 07777} {
		name := fmt.Sprintf("meta/mode/file_%04o", mode)
		c.CreateFile(t, name, []byte(name))
		c.Chmod(t, name, mode)
	}
	for _, mode := range []uint32{0, 0500, 0555, 0700, 0711, 0755, 0777, 01777, 02775, 03777, 07755} {
		name := fmt.Sprintf("meta/mode/dir_%04o", mode)
		c.CreateFile(t, name+"/inner", []byte(name))
		c.Chmod(t, name, mode)
	}

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

// compatCorpusLinks covers hardlink groups: within and across directories,
// large, of empty, sparse and attribute-laden files, and of every
// non-directory type.
func compatCorpusLinks(t *testing.T, c *compatCorpus) {
	c.CreateFile(t, "links/pair/a", c.text(3000))
	c.CreateHardlink(t, "links/pair/b", "links/pair/a")
	c.CreateFile(t, "links/cross/x/f", c.random(10000))
	c.CreateHardlink(t, "links/cross/y/f", "links/cross/x/f")
	c.CreateHardlink(t, "links/cross/z/deeper/f", "links/cross/x/f")
	c.CreateFile(t, "links/many/target", []byte("many"))
	for i := 0; i < 100; i++ {
		c.CreateHardlink(t, fmt.Sprintf("links/many/l%03d", i), "links/many/target")
	}
	c.CreateFile(t, "links/empty/a", nil)
	c.CreateHardlink(t, "links/empty/b", "links/empty/a")
	c.CreateSparseFile(t, "links/sparse/a", 3<<20, map[int64][]byte{1 << 20: c.random(100)})
	c.CreateHardlink(t, "links/sparse/b", "links/sparse/a")
	c.CreateFile(t, "links/meta/a", c.random(5000))
	c.Chmod(t, "links/meta/a", 04750)
	c.Chown(t, "links/meta/a", 70000, 70001)
	c.SetXattr(t, "links/meta/a", "user.link", []byte("shared by the group"))
	c.setTime("links/meta/a", 1650000000, 424242424)
	c.CreateHardlink(t, "links/meta/b", "links/meta/a")
	c.CreateHardlink(t, "links/meta/c", "links/meta/a")
	c.CreateFile(t, "links/big/a", c.text(3<<20))
	c.CreateHardlink(t, "links/big/b", "links/big/a")

	c.CreateFIFO(t, "links/special/fifo_a")
	c.CreateHardlink(t, "links/special/fifo_b", "links/special/fifo_a")
	c.CreateCharDev(t, "links/special/chr_a", 10, 200)
	c.CreateHardlink(t, "links/special/chr_b", "links/special/chr_a")
	c.CreateBlockDev(t, "links/special/blk_a", 8, 16)
	c.CreateHardlink(t, "links/special/blk_b", "links/special/blk_a")
	c.socket(t, "links/special/sock_a")
	c.CreateHardlink(t, "links/special/sock_b", "links/special/sock_a")
	c.CreateSymlink(t, "links/special/symlink_a", "../pair/a")
	c.CreateHardlink(t, "links/special/symlink_b", "links/special/symlink_a")
}

// compatCorpusXattrs covers extended attributes: empty, binary and long
// values, long names, many per inode, identical ones shared across inodes,
// every name prefix EROFS indexes, and xattrs on every file type.
func compatCorpusXattrs(t *testing.T, c *compatCorpus) {
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
	for i := 0; i < 100; i++ {
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
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("xattr/shared/f%02d", i)
		c.CreateFile(t, name, []byte{byte(i)})
		c.SetXattr(t, name, "user.shared", shared)
		c.SetXattr(t, name, "user.common", []byte("c"))
		c.SetXattr(t, name, "user.own", []byte(name))
	}
	c.CreateFile(t, "xattr/prefixes", []byte("x"))
	c.SetXattr(t, "xattr/prefixes", "user.p", []byte("user"))
	c.SetXattr(t, "xattr/prefixes", "trusted.p", []byte("trusted"))
	c.SetXattr(t, "xattr/prefixes", "security.p", []byte("security"))
	c.CreateFile(t, "xattr/selinux", []byte("x"))
	c.SetXattr(t, "xattr/selinux", "security.selinux", []byte("system_u:object_r:bin_t:s0\x00"))
	c.CreateFile(t, "xattr/capability", []byte("x"))
	c.Chmod(t, "xattr/capability", 0755)
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
	c.socket(t, "xattr/types/socket")
	c.lsetxattr(t, "xattr/types/socket", "trusted.socket", []byte("socket"))
}

// compatCorpusNames covers file names: every length up to 255 bytes, special
// characters, bytes that are not UTF-8, and names that sort as prefixes.
func compatCorpusNames(t *testing.T, c *compatCorpus) {
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

// compatCorpusDirs covers directories: empty, deeply nested, spanning many
// blocks with short, mixed and 255-byte names, entries that end exactly on,
// just short of and just past a 4KiB directory block, and one of each type.
func compatCorpusDirs(t *testing.T, c *compatCorpus) {
	c.CreateDir(t, "dirs/empty")
	c.CreateDir(t, "dirs/empty_chain/a/b/c/d")
	path := "dirs/deep"
	for depth := 1; depth <= 40; depth++ {
		path = fmt.Sprintf("%s/d%02d", path, depth)
		c.CreateFile(t, path+"/leaf", []byte(path))
	}
	for i := 0; i < 1000; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_short/%03d", i), nil)
	}
	for i := 0; i < 400; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_mixed/%0*d", 1+i%255, i), nil)
	}
	for i := 0; i < 100; i++ {
		c.CreateFile(t, fmt.Sprintf("dirs/wide_long/%s%03d", corpus.LongName('l', 252), i), nil)
	}
	for i := 0; i < 300; i++ {
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
	c.socket(t, "dirs/types/socket")
}

// compatCorpusSymlinks covers symlink targets of every length class up to
// PATH_MAX, around the inline limits, and unusual targets.
func compatCorpusSymlinks(t *testing.T, c *compatCorpus) {
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

// compatCorpusSpecial covers device, fifo and socket nodes, with device
// numbers past 8 bits up to the 12-bit major and 20-bit minor limits.
func compatCorpusSpecial(t *testing.T, c *compatCorpus) {
	c.CreateFIFO(t, "special/fifo")
	c.CreateFIFO(t, "special/fifo_0600")
	c.Chmod(t, "special/fifo_0600", 0600)
	for _, dev := range [][2]uint32{{1, 3}, {4, 64}, {10, 200}, {136, 1}, {255, 255}, {256, 0}, {0, 256}, {259, 65536}, {4095, 1048575}} {
		c.CreateCharDev(t, fmt.Sprintf("special/chr_%d_%d", dev[0], dev[1]), dev[0], dev[1])
		c.CreateBlockDev(t, fmt.Sprintf("special/blk_%d_%d", dev[0], dev[1]), dev[0], dev[1])
	}
	c.socket(t, "special/socket")
	c.socket(t, "special/socket_0700")
	c.Chmod(t, "special/socket_0700", 0700)
}

// compatMakeMergeLayers stages three layers whose overlay exercises every
// whiteout form, type changes in both directions, metadata overrides of files
// and directories, hardlink groups broken or removed by upper layers, and a
// name removed and re-added.
func compatMakeMergeLayers(t *testing.T, dirs []string) {
	t.Helper()
	require.Len(t, dirs, 3)

	lower := newCompatCorpus(t, dirs[0], compatSeed+1)
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
	lower.finish(t)

	middle := newCompatCorpus(t, dirs[1], compatSeed+2)
	middle.CreateFile(t, "keep_copy/random", shared)
	middle.CreateFile(t, "change/.wh.removed", nil)
	middle.CreateFile(t, "change/.wh.removed_dir", nil)
	middle.CreateFile(t, "change/.wh.never_existed", nil)
	middle.CreateFile(t, "change/opaque/.wh..wh..opq", nil)
	middle.CreateFile(t, "change/opaque/new", []byte("new"))
	middle.CreateFile(t, "change/replaced", middle.random(70000))
	middle.Chmod(t, "change/replaced", 0600)
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
	middle.Chmod(t, "change/meta_dir", 0700)
	middle.CreateFile(t, "links/b", []byte("breaks the group"))
	middle.CreateFile(t, "links/.wh.q", nil)
	middle.CreateFile(t, "links/.wh.whole", nil)
	middle.CreateFile(t, "links/new_a", middle.text(300))
	middle.CreateHardlink(t, "links/new_b", "links/new_a")
	middle.finish(t)

	upper := newCompatCorpus(t, dirs[2], compatSeed+3)
	upper.CreateFile(t, "change/readded", []byte("v3"))
	upper.CreateFile(t, "change/.wh.file_to_dir", nil)
	upper.CreateFile(t, "change/opaque/.wh.new", nil)
	upper.CreateFile(t, "change/opaque/newest", nil)
	upper.CreateFile(t, "fresh/deep/er/file", upper.text(2000))
	upper.CreateDir(t, "change/meta_dir")
	upper.SetXattr(t, "change/meta_dir", "user.dir", []byte("upper"))
	upper.setTime("change/meta_dir", 1800000000, 123)
	upper.finish(t)
}
