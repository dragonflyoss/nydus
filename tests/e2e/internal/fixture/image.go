// Package fixture provides the corpora and images every e2e suite reads:
// named source trees and `nydus build` layouts, built once and cached on
// disk across test binaries and runs.
package fixture

import (
	"fmt"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
)

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

// Layouts are the GA build configurations: every compressor, the chunk size
// extremes, chunk grouping, digest-less, aligned native, and tar input.
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

// MergedPrefix names a merged image: "merged-<layout>" is the three-layer
// overlay of the layers corpus, each layer built with <layout>.
const MergedPrefix = "merged-"

// HugePrefix names an image of the Huge corpus: "huge-<layout>".
const HugePrefix = "huge-"

// MergeLayouts are the layer layouts merged images are built with.
var MergeLayouts = []string{"zstd-4k", "erofs-lz4", "tar-zstd"}

// Matrix are the images the data-path contract cases run against: one
// meta-backed, one native, one tar-converted, one merged, and the files past
// 4GiB.
var Matrix = []string{"zstd-4k", "erofs-lz4", "tar-zstd", MergedPrefix + "zstd-4k", HugePrefix + "zstd"}

// LayoutByName returns the GA layout called name.
func LayoutByName(name string) (Layout, error) {
	for _, l := range Layouts {
		if l.Name == name {
			return l, nil
		}
	}
	return Layout{}, fmt.Errorf("no layout %q", name)
}

// Image is a built nydus image. Cached images are shared by every test:
// treat every path as read-only, and Copy the image before damaging it.
type Image struct {
	// Name is the layout name, or merged-<layout>.
	Name   string
	Layout Layout
	// Corpus names the corpus the image was built from.
	Corpus    string
	Bootstrap string
	BlobDir   string
	// Blobs are the full data blobs, one per layer, lowest first.
	Blobs  []string
	Merged bool
	// Source is the directory the image was built from; empty for merged
	// images, which reproduce an overlay rather than any one directory.
	Source string
	// Want is the tree every read path of the image must reproduce.
	Want []oracle.Entry
}

// Blob returns the single data blob of an unmerged image.
func (img Image) Blob() string {
	if len(img.Blobs) != 1 {
		panic(fmt.Sprintf("image %s has %d blobs", img.Name, len(img.Blobs)))
	}
	return img.Blobs[0]
}

// Compare is how a mount of the image is judged against Want: a merged
// bootstrap keeps each layer's link count, which a group broken by an upper
// layer no longer matches (KI-6).
func (img Image) Compare() oracle.CompareOptions {
	return oracle.CompareOptions{Nlink: !img.Merged}
}
