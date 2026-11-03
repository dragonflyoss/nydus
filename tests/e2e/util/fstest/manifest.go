package fstest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// EntryType is the file type of an Entry.
type EntryType string

// The file types of an Entry.
const (
	TypeReg     EntryType = "reg"
	TypeDir     EntryType = "dir"
	TypeSymlink EntryType = "symlink"
	TypeChr     EntryType = "chr"
	TypeBlk     EntryType = "blk"
	TypeFifo    EntryType = "fifo"
	TypeSocket  EntryType = "socket"
)

// Entry is the state of one path of a tree: what the source holds and
// what every read path of the image must report back. The manifest model
// records a tree as data, so unlike DiffTree it does not need the source
// tree on disk and judges compatibility images, overlays of several layers,
// tar views and exported layers alike.
type Entry struct {
	Path      Bytes     `json:"path"`
	Type      EntryType `json:"type"`
	Mode      uint32    `json:"mode"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	MtimeSec  int64     `json:"mtime_sec"`
	MtimeNsec int64     `json:"mtime_nsec"`
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
	// SHA256 of the content of regular files up to fullReadLimit.
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

// MarshalText encodes b as a Go-quoted string.
func (b Bytes) MarshalText() ([]byte, error) {
	return []byte(strconv.Quote(string(b))), nil
}

// UnmarshalText decodes the Go-quoted string MarshalText writes.
func (b *Bytes) UnmarshalText(text []byte) error {
	s, err := strconv.Unquote(string(text))
	*b = Bytes(s)

	return err
}

// ScanSource records the tree under root, including the data extents of
// the files too large to hash in full.
func ScanSource(t testing.TB, root string) []Entry {
	t.Helper()
	entries := ScanTree(t, root)
	for i := range entries {
		if entries[i].Type == TypeReg && entries[i].SHA256 == "" {
			entries[i].Extents = dataExtents(t, filepath.Join(root, string(entries[i].Path)))
		}
	}

	return entries
}

// ScanTree records every path under root, root itself aside: the root
// of an image is synthesized by the builder and carries its own xattrs.
func ScanTree(t testing.TB, root string) []Entry {
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

	assert.NoError(t, err)
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
		Mode:      st.Mode & 0o7777,
		UID:       st.Uid,
		GID:       st.Gid,
		MtimeSec:  st.Mtim.Sec,
		MtimeNsec: st.Mtim.Nsec,
	}

	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.Type = TypeDir

	case unix.S_IFREG:
		entry.Type = TypeReg

		entry.Size = st.Size
		if st.Size <= fullReadLimit {
			sum, err := HashFile(path)
			if err != nil {
				return Entry{}, err
			}

			entry.SHA256 = sum
		}

	case unix.S_IFLNK:
		entry.Type = TypeSymlink
		entry.Size = st.Size
		target, err := os.Readlink(path)
		if err != nil {
			return Entry{}, err
		}

		entry.Target = Bytes(target)

	case unix.S_IFCHR, unix.S_IFBLK:
		entry.Type = TypeChr

		if st.Mode&unix.S_IFMT == unix.S_IFBLK {
			entry.Type = TypeBlk
		}

		entry.Major = unix.Major(st.Rdev)
		entry.Minor = unix.Minor(st.Rdev)

	case unix.S_IFIFO:
		entry.Type = TypeFifo

	case unix.S_IFSOCK:
		entry.Type = TypeSocket

	default:
		return Entry{}, fmt.Errorf("%s: unsupported file type %o", rel, st.Mode&unix.S_IFMT)
	}

	if entry.Type != TypeDir {
		entry.Nlink = uint64(st.Nlink) //nolint:unconvert // Nlink is uint32 on arm64, uint64 on amd64.
		entry.inode = fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}

	xattrs, err := listXattrs(path)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", rel, err)
	}

	entry.Xattrs = xattrs

	return entry, nil
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

// withoutSockets drops the sockets a tarball cannot carry.
func withoutSockets(entries []Entry) []Entry {
	var out []Entry

	for _, entry := range entries {
		if entry.Type != TypeSocket {
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

	for _, entry := range withoutSockets(entries) {
		if !tarSafe(string(entry.Path)) || !tarSafe(string(entry.Target)) {
			continue
		}

		xattrs := entry.Xattrs
		entry.Xattrs = nil

		for name, value := range xattrs {
			if tarXattr(name, value) {
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
		if out[i].Type != TypeDir {
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
			if lower, ok := merged[entry.Path]; ok && lower.Type == TypeDir && entry.Type != TypeDir {
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

	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(string(a.Path), string(b.Path)) })
	regroupLinks(out, func(Entry) string { return "" })

	return out
}

// VerifyMount compares the tree under mnt with want, including the
// content of every regular file: small files by hash, larger ones by their
// extents, so a large file with no data at all is sampled as one hole.
func VerifyMount(t testing.TB, mnt string, want []Entry, opts CompareOptions) {
	t.Helper()
	CompareTree(t, want, ScanTree(t, mnt), opts)

	for _, entry := range want {
		if entry.Type == TypeReg && entry.SHA256 == "" {
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
func CompareTree(t testing.TB, want, got []Entry, opts CompareOptions) {
	t.Helper()
	const maxReported = 20

	normalize := func(entry Entry) Entry {
		entry.Extents = nil
		entry.inode = ""

		if !opts.Nlink || opts.Tar {
			entry.Nlink = 0
		}

		if opts.Tar && entry.Type != TypeReg {
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
				assert.Equal(t, w, g)
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
	if len(missing) > 0 || len(extra) > 0 || differ > 0 {
		t.FailNow()
	}
}
