/*
 * Copyright (c) 2023. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package tool

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeature(t *testing.T) {
	testsAdd := []struct {
		name     string
		features Features
		items    []Feature
		expect   Features
	}{
		{
			name:     "should successfully add items",
			features: Features{FeatureBatchSize: {}},
			items:    []Feature{FeatureTar2Rafs},
			expect:   Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
		},
		{
			name:     "should add nothing if duplicated",
			features: Features{FeatureBatchSize: {}},
			items:    []Feature{FeatureBatchSize},
			expect:   Features{FeatureBatchSize: {}},
		},
		{
			name:     "add should accept nil",
			features: Features{FeatureBatchSize: {}},
			items:    nil,
			expect:   Features{FeatureBatchSize: {}},
		},
	}
	for _, tt := range testsAdd {
		t.Run(tt.name, func(t *testing.T) {
			tt.features.Add(tt.items...)
			require.Equal(t, tt.expect, tt.features)
		})
	}

	testsNew := []struct {
		name   string
		items  []Feature
		expect Features
	}{
		{
			name:   "should successfully new Features",
			items:  []Feature{FeatureTar2Rafs, FeatureBatchSize},
			expect: Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
		},
		{
			name:   "should duplicate same items",
			items:  []Feature{FeatureBatchSize, FeatureBatchSize},
			expect: Features{FeatureBatchSize: {}},
		},
		{
			name:   "New should accept nil",
			items:  nil,
			expect: Features{},
		},
	}
	for _, tt := range testsNew {
		t.Run(tt.name, func(t *testing.T) {
			features := NewFeatures(tt.items...)
			require.Equal(t, tt.expect, features)
		})
	}

	testsRemove := []struct {
		name     string
		features Features
		items    []Feature
		expect   Features
	}{
		{
			name:     "should successfully remove items",
			features: Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			items:    []Feature{FeatureTar2Rafs},
			expect:   Features{FeatureBatchSize: {}},
		},
		{
			name:     "should remove item iff exists",
			features: Features{FeatureBatchSize: {}},
			items:    []Feature{FeatureBatchSize, FeatureTar2Rafs},
			expect:   Features{},
		},
		{
			name:     "Remove should accept nil",
			features: Features{FeatureBatchSize: {}},
			items:    nil,
			expect:   Features{FeatureBatchSize: {}},
		},
	}
	for _, tt := range testsRemove {
		t.Run(tt.name, func(t *testing.T) {
			tt.features.Remove(tt.items...)
			require.Equal(t, tt.expect, tt.features)
		})
	}

	testsContains := []struct {
		name     string
		features Features
		item     Feature
		expect   bool
	}{
		{
			name:     "should return contains",
			features: Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			item:     FeatureTar2Rafs,
			expect:   true,
		},
		{
			name:     "should return not contains",
			features: Features{FeatureBatchSize: {}},
			item:     FeatureTar2Rafs,
			expect:   false,
		},
		{
			name:     "Contains should accept empty string",
			features: Features{FeatureBatchSize: {}},
			item:     "",
			expect:   false,
		},
	}
	for _, tt := range testsContains {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, tt.features.Contains(tt.item))
		})
	}

	testsEquals := []struct {
		name     string
		features Features
		other    Features
		expect   bool
	}{
		{
			name:     "should successfully check equality",
			features: Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			other:    Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			expect:   true,
		},
		{
			name:     "should successfully check inequality with different length",
			features: Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			other:    Features{FeatureBatchSize: {}},
			expect:   false,
		},
		{
			name:     "should successfully check inequality with different items",
			features: Features{FeatureTar2Rafs: {}},
			other:    Features{FeatureBatchSize: {}},
			expect:   false,
		},
		{
			name:     "should ignore order",
			features: Features{FeatureBatchSize: {}, FeatureTar2Rafs: {}},
			other:    Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
			expect:   true,
		},
		{
			name:     "Equals should accept nil",
			features: Features{FeatureBatchSize: {}},
			other:    nil,
			expect:   false,
		},
	}
	for _, tt := range testsEquals {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, tt.features.Equals(tt.other))
		})
	}
}

func TestDetectFeature(t *testing.T) {
	tests := []struct {
		name    string
		feature Feature
		helpMsg []byte
		expect  bool
	}{
		{
			name:    "'--type tar-rafs' is supported in v2.2.0-239-gf5c08fcf",
			feature: FeatureTar2Rafs,
			expect:  true,
			helpMsg: []byte(`
			Create RAFS filesystems from directories, tar files or OCI images

			Usage: nydus-image create [OPTIONS] <SOURCE>
			
			Arguments:
			  <SOURCE>  source from which to build the RAFS filesystem
			
			Options:
			  -L, --log-file <log-file>
					  Log file path
			  -t, --type <type>
					  Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
			  -B, --bootstrap <bootstrap>
					  File path to save the generated RAFS metadata blob
			  -l, --log-level <log-level>
					  Log level: [default: info] [possible values: trace, debug, info, warn, error]
			  -D, --blob-dir <blob-dir>
					  Directory path to save generated RAFS metadata and data blobs
			  -b, --blob <blob>
					  File path to save the generated RAFS data blob
				  --blob-inline-meta
					  Inline RAFS metadata and blob metadata into the data blob
				  --blob-id <blob-id>
					  OSS object id for the generated RAFS data blob
				  --blob-data-size <blob-data-size>
					  Set data blob size for 'estargztoc-ref' conversion
				  --chunk-size <chunk-size>
					  Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
				  --batch-size <batch-size>
					  Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
				  --compressor <compressor>
					  Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
				  --digester <digester>
					  Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
			  -C, --config <config>
					  Configuration file for storage backend, cache and RAFS FUSE filesystem.
			  -v, --fs-version <fs-version>
					  Set RAFS format version number: [default: 6] [possible values: 5, 6]
				  --features <features>
					  Enable/disable features [possible values: blob-toc]
				  --chunk-dict <chunk-dict>
					  File path of chunk dictionary for data deduplication
				  --parent-bootstrap <parent-bootstrap>
					  File path of the parent/referenced RAFS metadata blob (optional)
				  --aligned-chunk
					  Align uncompressed data chunks to 4K, only for RAFS V5
				  --repeatable
					  Generate reproducible RAFS metadata
				  --whiteout-spec <whiteout-spec>
					  Set the type of whiteout specification: [default: oci] [possible values: oci, overlayfs, none]
				  --prefetch-policy <prefetch-policy>
					  Set data prefetch policy [default: none] [possible values: fs, blob, none]
			  -J, --output-json <output-json>
					  File path to save operation result in JSON format
			  -h, --help
					  Print help information
			`),
		},
		{
			name:    "'--batch-size' is supported in v2.2.0-239-gf5c08fcf",
			feature: FeatureBatchSize,
			expect:  true,
			helpMsg: []byte(`
			Create RAFS filesystems from directories, tar files or OCI images

			Usage: nydus-image create [OPTIONS] <SOURCE>
			
			Arguments:
			  <SOURCE>  source from which to build the RAFS filesystem
			
			Options:
			  -L, --log-file <log-file>
					  Log file path
			  -t, --type <type>
					  Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
			  -B, --bootstrap <bootstrap>
					  File path to save the generated RAFS metadata blob
			  -l, --log-level <log-level>
					  Log level: [default: info] [possible values: trace, debug, info, warn, error]
			  -D, --blob-dir <blob-dir>
					  Directory path to save generated RAFS metadata and data blobs
			  -b, --blob <blob>
					  File path to save the generated RAFS data blob
				  --blob-inline-meta
					  Inline RAFS metadata and blob metadata into the data blob
				  --blob-id <blob-id>
					  OSS object id for the generated RAFS data blob
				  --blob-data-size <blob-data-size>
					  Set data blob size for 'estargztoc-ref' conversion
				  --chunk-size <chunk-size>
					  Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
				  --batch-size <batch-size>
					  Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
				  --compressor <compressor>
					  Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
				  --digester <digester>
					  Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
			  -C, --config <config>
					  Configuration file for storage backend, cache and RAFS FUSE filesystem.
			  -v, --fs-version <fs-version>
					  Set RAFS format version number: [default: 6] [possible values: 5, 6]
				  --features <features>
					  Enable/disable features [possible values: blob-toc]
				  --chunk-dict <chunk-dict>
					  File path of chunk dictionary for data deduplication
				  --parent-bootstrap <parent-bootstrap>
					  File path of the parent/referenced RAFS metadata blob (optional)
				  --aligned-chunk
					  Align uncompressed data chunks to 4K, only for RAFS V5
				  --repeatable
					  Generate reproducible RAFS metadata
				  --whiteout-spec <whiteout-spec>
					  Set the type of whiteout specification: [default: oci] [possible values: oci, overlayfs, none]
				  --prefetch-policy <prefetch-policy>
					  Set data prefetch policy [default: none] [possible values: fs, blob, none]
			  -J, --output-json <output-json>
					  File path to save operation result in JSON format
			  -h, --help
					  Print help information
			`),
		},
		{
			name:    "'--batch-size' is not supported in v2.2.0-163-g180f6d2c",
			feature: FeatureBatchSize,
			expect:  false,
			helpMsg: []byte(`
			Create RAFS filesystems from directories, tar files or OCI images

			Usage: nydus-image create [OPTIONS] <SOURCE>
			
			Arguments:
			  <SOURCE>  source from which to build the RAFS filesystem
			
			Options:
			  -L, --log-file <log-file>
					  Log file path
			  -t, --type <type>
					  Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
			  -B, --bootstrap <bootstrap>
					  File path to save the generated RAFS metadata blob
			  -l, --log-level <log-level>
					  Log level: [default: info] [possible values: trace, debug, info, warn, error]
			  -D, --blob-dir <blob-dir>
					  Directory path to save generated RAFS metadata and data blobs
			  -b, --blob <blob>
					  File path to save the generated RAFS data blob
				  --blob-inline-meta
					  Inline RAFS metadata and blob metadata into the data blob
				  --blob-id <blob-id>
					  OSS object id for the generated RAFS data blob
				  --blob-data-size <blob-data-size>
					  Set data blob size for 'estargztoc-ref' conversion
				  --chunk-size <chunk-size>
					  Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
				  --compressor <compressor>
					  Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
				  --digester <digester>
					  Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
			  -C, --config <config>
					  Configuration file for storage backend, cache and RAFS FUSE filesystem.
			  -v, --fs-version <fs-version>
					  Set RAFS format version number: [default: 6] [possible values: 5, 6]
				  --features <features>
					  Enable/disable features [possible values: blob-toc]
				  --chunk-dict <chunk-dict>
					  File path of chunk dictionary for data deduplication
				  --parent-bootstrap <parent-bootstrap>
					  File path of the parent/referenced RAFS metadata blob (optional)
				  --aligned-chunk
					  Align uncompressed data chunks to 4K, only for RAFS V5
				  --repeatable
					  Generate reproducible RAFS metadata
				  --whiteout-spec <whiteout-spec>
					  Set the type of whiteout specification: [default: oci] [possible values: oci, overlayfs, none]
				  --prefetch-policy <prefetch-policy>
					  Set data prefetch policy [default: none] [possible values: fs, blob, none]
			  -J, --output-json <output-json>
					  File path to save operation result in JSON format
			  -h, --help
					  Print help information
			`),
		},
		{
			name:    "'--encrypt' is supported in v2.2.0-261-g22ad0e2c",
			feature: FeatureEncrypt,
			expect:  true,
			helpMsg: []byte(`
			Create RAFS filesystems from directories, tar files or OCI images

			Usage: nydus-image create [OPTIONS] <SOURCE>

			Arguments:
			<SOURCE>  source from which to build the RAFS filesystem

			Options:
			-L, --log-file <log-file>
					Log file path
			-t, --type <type>
					Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
			-B, --bootstrap <bootstrap>
					File path to save the generated RAFS metadata blob
			-l, --log-level <log-level>
					Log level: [default: info] [possible values: trace, debug, info, warn, error]
			-D, --blob-dir <blob-dir>
					Directory path to save generated RAFS metadata and data blobs
			-b, --blob <blob>
					File path to save the generated RAFS data blob
				--blob-inline-meta
					Inline RAFS metadata and blob metadata into the data blob
				--blob-id <blob-id>
					OSS object id for the generated RAFS data blob
				--blob-data-size <blob-data-size>
					Set data blob size for 'estargztoc-ref' conversion
				--chunk-size <chunk-size>
					Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
				--batch-size <batch-size>
					Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
				--compressor <compressor>
					Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
				--digester <digester>
					Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
			-C, --config <config>
					Configuration file for storage backend, cache and RAFS FUSE filesystem.
			-v, --fs-version <fs-version>
					Set RAFS format version number: [default: 6] [possible values: 5, 6]
				--features <features>
					Enable/disable features [possible values: blob-toc]
				--chunk-dict <chunk-dict>
					File path of chunk dictionary for data deduplication
				--parent-bootstrap <parent-bootstrap>
					File path of the parent/referenced RAFS metadata blob (optional)
				--aligned-chunk
					Align uncompressed data chunks to 4K, only for RAFS V5
				--repeatable
					Generate reproducible RAFS metadata
				--whiteout-spec <whiteout-spec>
					Set the type of whiteout specification: [default: oci] [possible values: oci, overlayfs, none]
				--prefetch-policy <prefetch-policy>
					Set data prefetch policy [default: none] [possible values: fs, blob, none]
			-J, --output-json <output-json>
					File path to save operation result in JSON format
			-E, --encrypt
					Encrypt the generated RAFS metadata and data blobs
			-h, --help
					Print help information
			`),
		},

		{
			name:    "'--type tar-rafs' is not supported in v2.1.4",
			feature: FeatureTar2Rafs,
			expect:  false,
			helpMsg: []byte(`
			nydus-image-create 
			Creates a nydus image from source
			
			USAGE:
				nydus-image create [FLAGS] [OPTIONS] <SOURCE>... --blob <blob> --bootstrap <bootstrap> --fs-version <fs-version> --whiteout-spec <whiteout-spec>
			
			FLAGS:
				-A, --aligned-chunk       Align data chunks to 4K
					--disable-check       disable validation of metadata after building
				-h, --help                Prints help information
					--inline-bootstrap    append bootstrap data to blob
				-R, --repeatable          generate reproducible nydus image
				-V, --version             Prints version information
			
			OPTIONS:
					--backend-config <backend-config>
						[deprecated!] Blob storage backend config - JSON string, only support localfs for compatibility
			
					--backend-type <backend-type>
						[deprecated!] Blob storage backend type, only support localfs for compatibility. Try use --blob instead.
						[possible values: localfs]
				-b, --blob <blob>                            path to store nydus image's data blob
				-D, --blob-dir <blob-dir>                    directory to store nydus image's metadata and data blob
					--blob-id <blob-id>                      blob id (as object id in backend/oss)
					--blob-meta <blob-meta>                  path to store nydus blob metadata
					--blob-offset <blob-offset>
						add an offset for compressed blob (is only used to put the blob in the tarball) [default: 0]
			
				-B, --bootstrap <bootstrap>                  path to store the nydus image's metadata blob
				-M, --chunk-dict <chunk-dict>                Specify a chunk dictionary for chunk deduplication
				-S, --chunk-size <chunk-size>
						size of nydus image data chunk, must be power of two and between 0x1000-0x100000: [default: 0x100000]
			
				-c, --compressor <compressor>
						algorithm to compress image data blob: [default: lz4_block]  [possible values: none, lz4_block, gzip, zstd]
			
				-d, --digester <digester>
						algorithm to digest inodes and data chunks: [default: blake3]  [possible values: blake3, sha256]
			
				-v, --fs-version <fs-version>
						version number of nydus image format: [default: 5]  [possible values: 5, 6]
			
				-o, --log-file <log-file>                    Specify log file name
				-l, --log-level <log-level>
						Specify log level: [default: info]  [possible values: trace, debug, info, warn, error]
			
				-J, --output-json <output-json>              JSON file output path for result
				-p, --parent-bootstrap <parent-bootstrap>    path to parent/referenced image's metadata blob (optional)
				-P, --prefetch-policy <prefetch-policy>
						blob data prefetch policy [default: none]  [possible values: fs, blob, none]
			
				-t, --source-type <source-type>
						type of the source: [default: directory]  [possible values: directory, stargz_index]
			
				-W, --whiteout-spec <whiteout-spec>
						type of whiteout specification: [default: oci]  [possible values: oci, overlayfs, none]
			
			
			ARGS:
				<SOURCE>...    source path to build the nydus image from
			`),
		},
		{
			name:    "'--batch-size' is not supported in v1.1.2",
			feature: FeatureBatchSize,
			expect:  false,
			helpMsg: []byte(`
			nydus-image-create 
			Create a nydus format accelerated container image
			
			USAGE:
				nydus-image create [FLAGS] [OPTIONS] <SOURCE> --blob <blob> --bootstrap <bootstrap> --whiteout-spec <whiteout-spec>
			
			FLAGS:
					--aligned-chunk    Whether to align chunks into blobcache
					--disable-check    Disable to validate bootstrap file after building
				-h, --help             Prints help information
					--repeatable       Produce environment independent image
				-V, --version          Prints version information
			
			OPTIONS:
					--backend-config <backend-config>
						[deprecated!] Blob storage backend config - JSON string, only support localfs for compatibility
			
					--backend-type <backend-type>
						[deprecated!] Blob storage backend type, only support localfs for compatibility. Try use --blob instead.
						[possible values: localfs]
					--blob <blob>                            A path to blob file which stores nydus image data portion
					--blob-dir <blob-dir>
						A directory where blob files are saved named as their sha256 digest. It's very useful when multiple layers
						are built at the same time.
					--blob-id <blob-id>                      blob id (as object id in backend/oss)
					--bootstrap <bootstrap>                  A path to bootstrap file which stores nydus image metadata portion
					--chunk-dict <chunk-dict>
						specify a chunk dictionary file in bootstrap/db format for chunk deduplication.
			
					--compressor <compressor>
						how blob will be compressed: none, lz4_block (default) [default: lz4_block]
			
					--digester <digester>
						how inode and blob chunk will be digested: blake3 (default), sha256 [default: blake3]
			
					--log-level <log-level>
						Specify log level: trace, debug, info, warn, error [default: info]  [possible values: trace, debug, info,
						warn, error]
					--output-json <output-json>              JSON output path for build result
					--parent-bootstrap <parent-bootstrap>    bootstrap file path of parent (optional)
					--prefetch-policy <prefetch-policy>
						Prefetch policy: fs(issued from Fs layer), blob(issued from backend/blob layer), none(no readahead is
						needed) [default: none]
					--source-type <source-type>
						source type [default: directory]  [possible values: directory, stargz_index]
			
					--whiteout-spec <whiteout-spec>
						decide which whiteout spec to follow: "oci" or "overlayfs" [default: oci]  [possible values: oci, overlayfs]
			
			
			ARGS:
				<SOURCE>    source path
			`),
		},
		{
			name:    "'--type tar-rafs' is not supported in v0.1.0",
			feature: FeatureTar2Rafs,
			expect:  false,
			helpMsg: []byte(`
			nydus-image-create 
			dump image bootstrap and upload blob to storage backend
			
			USAGE:
				nydus-image create [FLAGS] [OPTIONS] <SOURCE> --bootstrap <bootstrap> --whiteout-spec <whiteout-spec>
			
			FLAGS:
					--aligned-chunk    Whether to align chunks into blobcache
					--disable-check    Disable to validate bootstrap file after building
				-h, --help             Prints help information
					--repeatable       Produce environment independent image
				-V, --version          Prints version information
			
			OPTIONS:
					--backend-config <backend-config>              blob storage backend config (JSON string)
					--backend-config-file <backend-config-file>    blob storage backend config (JSON file)
					--backend-type <backend-type>                  blob storage backend type (enable blob upload if specified)
					--blob <blob>                                  blob file path
					--blob-id <blob-id>                            blob id (as object id in backend)
					--bootstrap <bootstrap>                        bootstrap file path (required)
					--compressor <compressor>
						how blob will be compressed: none, lz4_block (default) [default: lz4_block]
			
					--digester <digester>
						how inode and blob chunk will be digested: blake3 (default), sha256 [default: blake3]
			
					--log-level <log-level>
						Specify log level: trace, debug, info, warn, error [default: info]  [possible values: trace, debug, info,
						warn, error]
					--output-json <output-json>                    JSON output path for build result
					--parent-bootstrap <parent-bootstrap>          bootstrap file path of parent (optional)
					--prefetch-policy <prefetch-policy>
						Prefetch policy: fs(issued from Fs layer), blob(issued from backend/blob layer), none(no readahead is
						needed) [default: none]
					--source-type <source-type>
						source type [default: directory]  [possible values: directory, stargz_index]
			
					--whiteout-spec <whiteout-spec>
						decide which whiteout spec to follow: "oci" or "overlayfs" [default: oci]  [possible values: oci, overlayfs]
			
			
			ARGS:
				<SOURCE>    source path
			`),
		},
		{
			name:    "'--encrypt' is not supported in v2.2.0",
			feature: FeatureEncrypt,
			expect:  false,
			helpMsg: []byte(`
			Create RAFS filesystems from directories, tar files or OCI images

			Usage: nydus-image create [OPTIONS] <SOURCE>

			Arguments:
			<SOURCE>  source from which to build the RAFS filesystem

			Options:
			-L, --log-file <log-file>
					Log file path
			-t, --type <type>
					Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
			-B, --bootstrap <bootstrap>
					File path to save the generated RAFS metadata blob
			-l, --log-level <log-level>
					Log level: [default: info] [possible values: trace, debug, info, warn, error]
			-D, --blob-dir <blob-dir>
					Directory path to save generated RAFS metadata and data blobs
			-b, --blob <blob>
					File path to save the generated RAFS data blob
				--blob-inline-meta
					Inline RAFS metadata and blob metadata into the data blob
				--blob-id <blob-id>
					OSS object id for the generated RAFS data blob
				--blob-data-size <blob-data-size>
					Set data blob size for 'estargztoc-ref' conversion
				--chunk-size <chunk-size>
					Set the size of data chunks, must be power of two and between 0x1000-0x1000000:
				--batch-size <batch-size>
					Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
				--compressor <compressor>
					Algorithm to compress data chunks: [default: zstd] [possible values: none, lz4_block, zstd]
				--digester <digester>
					Algorithm to digest data chunks: [default: blake3] [possible values: blake3, sha256]
			-C, --config <config>
					Configuration file for storage backend, cache and RAFS FUSE filesystem.
			-v, --fs-version <fs-version>
					Set RAFS format version number: [default: 6] [possible values: 5, 6]
				--features <features>
					Enable/disable features [possible values: blob-toc]
				--chunk-dict <chunk-dict>
					File path of chunk dictionary for data deduplication
				--parent-bootstrap <parent-bootstrap>
					File path of the parent/referenced RAFS metadata blob (optional)
				--aligned-chunk
					Align uncompressed data chunks to 4K, only for RAFS V5
				--repeatable
					Generate reproducible RAFS metadata
				--whiteout-spec <whiteout-spec>
					Set the type of whiteout specification: [default: oci] [possible values: oci, overlayfs, none]
				--prefetch-policy <prefetch-policy>
					Set data prefetch policy [default: none] [possible values: fs, blob, none]
			-J, --output-json <output-json>
					File path to save operation result in JSON format
			-h, --help
					Print help information
			`),
		},
		{
			name:    "detectFeature should support empty input",
			feature: "",
			expect:  false,
			helpMsg: []byte(`
			OPTIONS:
					--type <type>
						[deprecated!] Conversion type.
						[possible values: tar-rafs]
			`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expect, detectFeature(tt.helpMsg, tt.feature))
		})
	}
}

func TestDetectFeatures(t *testing.T) {
	testsCompare := []struct {
		name            string
		resetGlobal     bool
		disableTar2Rafs bool
		helpText        []byte
		required        Features
		detected        Features
		expectErr       bool
	}{
		{
			name:            "should satisfy required features in v2.2.0-239-gf5c08fcf",
			resetGlobal:     true,
			disableTar2Rafs: false,
			helpText: []byte(`
			Options:
			  -t, --type <type>
					  Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
				  --batch-size <batch-size>
					  Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
			`),
			required:  Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
			detected:  Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
			expectErr: false,
		},
		{
			name:            "should not support '--encrypt', '--batch-size' or '--type tar-rafs' in v2.1.4",
			resetGlobal:     true,
			disableTar2Rafs: true,
			helpText: []byte(`
			nydus-image-create 
			Creates a nydus image from source
			
			USAGE:
				nydus-image create [FLAGS] [OPTIONS] <SOURCE>... --blob <blob> --bootstrap <bootstrap> --fs-version <fs-version> --whiteout-spec <whiteout-spec>
			
			FLAGS:
				-A, --aligned-chunk       Align data chunks to 4K
					--disable-check       disable validation of metadata after building
				-h, --help                Prints help information
					--inline-bootstrap    append bootstrap data to blob
				-R, --repeatable          generate reproducible nydus image
				-V, --version             Prints version information
			
			OPTIONS:
					--backend-config <backend-config>
						[deprecated!] Blob storage backend config - JSON string, only support localfs for compatibility
			
					--backend-type <backend-type>
						[deprecated!] Blob storage backend type, only support localfs for compatibility. Try use --blob instead.
						[possible values: localfs]
				-b, --blob <blob>                            path to store nydus image's data blob
				-D, --blob-dir <blob-dir>                    directory to store nydus image's metadata and data blob
					--blob-id <blob-id>                      blob id (as object id in backend/oss)
					--blob-meta <blob-meta>                  path to store nydus blob metadata
					--blob-offset <blob-offset>
						add an offset for compressed blob (is only used to put the blob in the tarball) [default: 0]
			
				-B, --bootstrap <bootstrap>                  path to store the nydus image's metadata blob
				-M, --chunk-dict <chunk-dict>                Specify a chunk dictionary for chunk deduplication
				-S, --chunk-size <chunk-size>
						size of nydus image data chunk, must be power of two and between 0x1000-0x100000: [default: 0x100000]
			
				-c, --compressor <compressor>
						algorithm to compress image data blob: [default: lz4_block]  [possible values: none, lz4_block, gzip, zstd]
			
				-d, --digester <digester>
						algorithm to digest inodes and data chunks: [default: blake3]  [possible values: blake3, sha256]
			
				-v, --fs-version <fs-version>
						version number of nydus image format: [default: 5]  [possible values: 5, 6]
			
				-o, --log-file <log-file>                    Specify log file name
				-l, --log-level <log-level>
						Specify log level: [default: info]  [possible values: trace, debug, info, warn, error]
			
				-J, --output-json <output-json>              JSON file output path for result
				-p, --parent-bootstrap <parent-bootstrap>    path to parent/referenced image's metadata blob (optional)
				-P, --prefetch-policy <prefetch-policy>
						blob data prefetch policy [default: none]  [possible values: fs, blob, none]
			
				-t, --source-type <source-type>
						type of the source: [default: directory]  [possible values: directory, stargz_index]
			
				-W, --whiteout-spec <whiteout-spec>
						type of whiteout specification: [default: oci]  [possible values: oci, overlayfs, none]
			
			
			ARGS:
				<SOURCE>...    source path to build the nydus image from
			`),
			required:  Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}, FeatureEncrypt: {}},
			detected:  Features{},
			expectErr: false,
		},
		{
			name:            "should ignore '--type tar-rafs' if disabled",
			resetGlobal:     true,
			disableTar2Rafs: true,
			helpText: []byte(`
			Options:
			  -t, --type <type>
					  Conversion type: [default: dir-rafs] [possible values: directory, dir-rafs, estargz-rafs, estargz-ref, estargztoc-ref, tar-rafs, tar-tarfs, targz-rafs, targz-ref, stargz_index]
				  --batch-size <batch-size>
					  Set the batch size to merge small chunks, must be power of two, between 0x1000-0x1000000 or be zero: [default: 0]
			`),
			required:  Features{FeatureTar2Rafs: {}, FeatureBatchSize: {}},
			detected:  Features{FeatureBatchSize: {}},
			expectErr: false,
		},
		{
			name:            "should return error if required features changed in different calls",
			resetGlobal:     false,
			disableTar2Rafs: false,
			helpText:        nil,
			required:        Features{},
			detected:        nil,
			expectErr:       true,
		},
	}
	for _, tt := range testsCompare {
		t.Run(tt.name, func(t *testing.T) {
			if tt.resetGlobal {
				// Reset global variables.
				requiredFeatures = Features{}
				detectedFeatures = Features{}
				detectFeaturesOnce = sync.Once{}
				disableTar2Rafs = tt.disableTar2Rafs
			}
			detected, err := DetectFeatures("", tt.required, func(_ string) []byte { return tt.helpText })
			require.Equal(t, tt.expectErr, err != nil)
			require.Equal(t, tt.detected, detected)
		})
	}
}
