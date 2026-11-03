package fixture

import "testing"

// Layout is one `nydus build` configuration.
type Layout struct {
	Name string
	Args []string
	// Native layouts (erofs-*) carry no blob meta and need no cache to
	// mount; the kernel can read them directly.
	Native bool
	// Tar layouts stream-convert an OCI layer tarball of the corpus, as
	// nydusify does, instead of walking the directory.
	Tar bool
}

// Compressor returns the layout's --compressor argument, if any.
func (l Layout) Compressor() string {
	for i, arg := range l.Args {
		if arg == "--compressor" && i+1 < len(l.Args) {
			return l.Args[i+1]
		}
	}

	return ""
}

// Layouts are the GA `nydus build` layouts every build suite covers.
var Layouts = []Layout{
	{Name: "zstd", Args: []string{"--compressor", "zstd"}},
	{Name: "zstd-4k", Args: []string{"--compressor", "zstd", "--chunk-size", "4096"}},
	{Name: "zstd-4k-group-64k", Args: []string{"--compressor", "zstd", "--chunk-size", "4096", "--chunk-group-minimum-size", "65536"}},
	{Name: "zstd-8m", Args: []string{"--compressor", "zstd", "--chunk-size", "8388608"}},
	{Name: "zstd-no-digest", Args: []string{"--compressor", "zstd", "--digester", "none"}},
	{Name: "lz4-64k", Args: []string{"--compressor", "lz4", "--chunk-size", "65536"}},
	{Name: "none-4k", Args: []string{"--compressor", "none", "--chunk-size", "4096"}},
	{Name: "erofs-none", Native: true, Args: []string{"--compressor", "erofs-none"}},
	{Name: "erofs-none-64k-align-64k", Native: true, Args: []string{"--compressor", "erofs-none", "--chunk-size", "65536", "--erofs-data-alignment", "65536"}},
	{Name: "erofs-lz4", Native: true, Args: []string{"--compressor", "erofs-lz4"}},
	{Name: "erofs-zstd", Native: true, Args: []string{"--compressor", "erofs-zstd"}},
	{Name: "tar-zstd", Tar: true, Args: []string{"--compressor", "zstd"}},
	{Name: "tar-erofs-lz4", Tar: true, Native: true, Args: []string{"--compressor", "erofs-lz4"}},
}

const (
	// MergedPrefix names, before a layout name, the merged image of the
	// Layers corpus built with that layout.
	MergedPrefix = "merged-"

	// HugePrefix names, before a layout name, the image of the Huge corpus
	// built with that layout.
	HugePrefix = "huge-"
)

// MergeLayouts are the layouts whose merged images the suites build.
var MergeLayouts = []string{"zstd-4k", "erofs-lz4", "tar-zstd"}

// Matrix names the images, as Get takes them, that the contract Data cases
// run against.
var Matrix = []string{"zstd-4k", "erofs-lz4", "tar-zstd", MergedPrefix + "zstd-4k", HugePrefix + "zstd"}

// MustLayout returns the GA layout called name, failing t when there is none.
func MustLayout(t testing.TB, name string) Layout {
	t.Helper()
	for _, l := range Layouts {
		if l.Name == name {
			return l
		}
	}

	t.Fatalf("no layout %q", name)

	return Layout{}
}
