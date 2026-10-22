package oracle

// The manifest model records a tree as data: every path with its type,
// metadata, content hash (or data extents) and hardlink group. Unlike
// DiffTree it does not need the source tree on disk, so it judges golden
// images, overlays of several layers, tar views and exported layers alike.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Entry is the state of one path of a tree: what the source holds and
// what every read path of the image must report back.
type Entry struct {
	Path      Bytes  `json:"path"`
	Type      string `json:"type"`
	Mode      uint32 `json:"mode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	MtimeSec  int64  `json:"mtime_sec"`
	MtimeNsec int64  `json:"mtime_nsec"`
	// Size of regular files and symlinks.
	Size int64 `json:"size,omitempty"`
	// Nlink of non-directories.
	Nlink  uint64 `json:"nlink,omitempty"`
	Major  uint32 `json:"major,omitempty"`
	Minor  uint32 `json:"minor,omitempty"`
	Target Bytes  `json:"target,omitempty"`
	// Link is the smallest path of the entry's hardlink group, if any.
	Link   Bytes            `json:"link,omitempty"`
	Xattrs map[string]Bytes `json:"xattrs,omitempty"`
	// SHA256 of the content of regular files up to FullReadLimit.
	SHA256 string `json:"sha256,omitempty"`
	// Extents are the data of larger regular files; the rest reads as zeros.
	Extents []Extent `json:"extents,omitempty"`

	// inode identifies the entry's inode while a tree is scanned.
	inode string
}

// Bytes is a byte string (a file name, link target or xattr value) that
// round-trips through JSON as a Go-quoted string, so names and values that are
// not valid UTF-8 survive.
type Bytes string

func (b Bytes) MarshalText() ([]byte, error) {
	return []byte(strconv.Quote(string(b))), nil
}

func (b *Bytes) UnmarshalText(text []byte) error {
	s, err := strconv.Unquote(string(text))
	*b = Bytes(s)
	return err
}

// ScanSource records the tree under root, including the data extents of
// the files too large to hash in full.
func ScanSource(t env.TB, root string) []Entry {
	t.Helper()
	entries := ScanTree(t, root)
	for i := range entries {
		if entries[i].Type == "reg" && entries[i].SHA256 == "" {
			entries[i].Extents = DataExtents(t, filepath.Join(root, string(entries[i].Path)))
		}
	}
	return entries
}

// ScanTree records every path under root, root itself aside: the root
// of an image is synthesized by the builder and carries its own xattrs.
func ScanTree(t env.TB, root string) []Entry {
	t.Helper()
	var entries []Entry
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry, err := scanPath(path, rel)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	require.NoError(t, err, "scanning %s", root)
	assignLinks(entries)
	return entries
}

func scanPath(path, rel string) (Entry, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return Entry{}, err
	}
	entry := Entry{
		Path:      Bytes(rel),
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
		if st.Size <= FullReadLimit {
			sum, err := hashFile(path)
			if err != nil {
				return Entry{}, err
			}
			entry.SHA256 = sum
		}
	case unix.S_IFLNK:
		entry.Type = "symlink"
		entry.Size = st.Size
		target, err := os.Readlink(path)
		if err != nil {
			return Entry{}, err
		}
		entry.Target = Bytes(target)
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
		return Entry{}, fmt.Errorf("%s: unsupported file type %o", rel, st.Mode&unix.S_IFMT)
	}
	if entry.Type != "dir" {
		entry.Nlink = st.Nlink
		entry.inode = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	xattrs, err := listXattrs(path)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", rel, err)
	}
	entry.Xattrs = xattrs
	return entry, nil
}

func hashFile(path string) (string, error) {
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

// listXattrs returns the xattrs of path without following symlinks,
// less the trusted.nydus.* ones the builder adds for the runtime.
func listXattrs(path string) (map[string]Bytes, error) {
	size, err := unix.Llistxattr(path, nil)
	// A nydus mount of an image without any xattr answers EOPNOTSUPP.
	if errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil || size == 0 {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}
	var xattrs map[string]Bytes
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
			xattrs = map[string]Bytes{}
		}
		xattrs[name] = Bytes(value[:size])
	}
	return xattrs, nil
}

// assignLinks points every member of a hardlink group at the group's
// smallest path, which identifies the group the same way in every tree.
func assignLinks(entries []Entry) {
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

// regroupLinks recomputes Link after entries were dropped or replaced,
// using the group each entry was in (keyed by prefix, e.g. its layer).
func regroupLinks(entries []Entry, prefix func(Entry) string) {
	for i := range entries {
		entries[i].inode = ""
		if entries[i].Link != "" {
			entries[i].inode = prefix(entries[i]) + string(entries[i].Link)
		}
	}
	assignLinks(entries)
	for i := range entries {
		entries[i].inode = ""
	}
}

// WithoutSockets drops the sockets a tarball cannot carry.
func WithoutSockets(entries []Entry) []Entry {
	var out []Entry
	for _, entry := range entries {
		if entry.Type != "socket" {
			out = append(out, entry)
		}
	}
	regroupLinks(out, func(Entry) string { return "" })
	return out
}

// TarView is the tree an image built from WriteTar's tarball of
// entries holds.
func TarView(entries []Entry) []Entry {
	var out []Entry
	for _, entry := range WithoutSockets(entries) {
		if !TarSafe(string(entry.Path)) || !TarSafe(string(entry.Target)) {
			continue
		}
		xattrs := entry.Xattrs
		entry.Xattrs = nil
		for name, value := range xattrs {
			if TarXattr(name, value) {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]Bytes{}
				}
				entry.Xattrs[name] = value
			}
		}
		out = append(out, entry)
	}
	regroupLinks(out, func(Entry) string { return "" })
	// A tarball's hardlinks are all the links an inode gets.
	members := map[Bytes]uint64{}
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

// Overlay applies OCI layer semantics to the layer trees, lowest first:
// an opaque marker hides everything below in its directory, `.wh.<name>`
// removes <name> and its subtree from below, a non-directory replaces
// whatever is below, and directories merge with the upper metadata winning.
// Hardlink groups never span layers.
func Overlay(layers ...[]Entry) []Entry {
	const whiteoutPrefix = ".wh."
	const opaqueMarker = ".wh..wh..opq"
	split := func(path Bytes) (string, string) {
		p := string(path)
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			return p[:i], p[i+1:]
		}
		return "", p
	}
	merged := map[Bytes]Entry{}
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
				entry.Link = Bytes(fmt.Sprintf("%d/%s", layer, entry.Link))
			}
			merged[entry.Path] = entry
		}
	}

	out := make([]Entry, 0, len(merged))
	for _, entry := range merged {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	regroupLinks(out, func(Entry) string { return "" })
	return out
}

// VerifyMount compares the tree under mnt with want, including the
// content of every regular file.
func VerifyMount(t env.TB, mnt string, want []Entry, opts CompareOptions) {
	t.Helper()
	CompareTree(t, want, ScanTree(t, mnt), opts)
	for _, entry := range want {
		if len(entry.Extents) > 0 {
			VerifyExtents(t, filepath.Join(mnt, string(entry.Path)), entry.Size, entry.Extents)
		}
	}
}

// CompareOptions relaxes a comparison for what a read path cannot
// carry.
type CompareOptions struct {
	// Nlink compares the link count of non-directories.
	Nlink bool
	// Tar compares an exported layer: no link counts, and hardlinks of
	// regular files only.
	Tar bool
}

// CompareTree fails the test unless got has exactly the paths of want,
// each with the same attributes and content.
func CompareTree(t env.TB, want, got []Entry, opts CompareOptions) {
	t.Helper()
	const maxReported = 20
	normalize := func(entry Entry) Entry {
		entry.Extents = nil
		entry.inode = ""
		if !opts.Nlink || opts.Tar {
			entry.Nlink = 0
		}
		if opts.Tar && entry.Type != "reg" {
			entry.Link = ""
		}
		return entry
	}

	gotByPath := make(map[Bytes]Entry, len(got))
	for _, entry := range got {
		gotByPath[entry.Path] = entry
	}
	var missing, extra []string
	differ := 0
	for _, w := range want {
		g, ok := gotByPath[w.Path]
		if !ok {
			missing = append(missing, strconv.Quote(string(w.Path)))
			continue
		}
		delete(gotByPath, w.Path)
		if w, g := normalize(w), normalize(g); !reflect.DeepEqual(w, g) {
			differ++
			if differ <= maxReported {
				assert.Equal(t, w, g, "%q differs", w.Path)
			}
		}
	}
	for path := range gotByPath {
		extra = append(extra, strconv.Quote(string(path)))
	}

	report := func(what string, paths []string) {
		if len(paths) > 0 {
			shown := paths[:min(len(paths), maxReported)]
			t.Errorf("%d %s paths, including: %s", len(paths), what, strings.Join(shown, ", "))
		}
	}
	report("missing", missing)
	report("unexpected", extra)
	if differ > 0 {
		t.Errorf("%d entries differ", differ)
	}
	if t.Failed() {
		t.FailNow()
	}
}
