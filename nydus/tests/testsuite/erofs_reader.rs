//! Tests for `ErofsReader`: fixture images are built through the public
//! `build` module and then read back through the reader.

use crate::fixture;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tempfile::{tempdir, NamedTempFile, TempDir};

use nydus::build::{build_image, BuildImageOptions, NativeLayout};
use nydus_backend::{BlobBackend, Local, ReadContext};
use nydus_core::build::blob_chunk::{BlobLayout, BlobWriter};
use nydus_core::build::bootstrap::render_bootstrap;
use nydus_core::build::inode::{build_tree, resolve_chunk_addrs, ChildRef, InodeData, InodeInfo};
use nydus_core::ErofsReader;
use nydus_format::blob::{BlobFooter, BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{
    erofs_extended_i_format, erofs_xattr_ibody_size, ErofsChunkAddr, ErofsDeviceSlot, ErofsInode,
    ErofsInodeExtended, ErofsSuperblock, XattrEntry, ZAlgorithm, ZComprCfgs, EROFS_BLKSZBITS,
    EROFS_BLOCK_SIZE, EROFS_FT_REG_FILE, EROFS_INODE_COMPRESSED_FULL, EROFS_SB_BASE_SIZE,
    EROFS_SLOTSIZE, EROFS_SUPER_OFFSET, EROFS_XATTR_INDEX_USER, Z_EROFS_ADVISE_FRAGMENT_PCLUSTER,
    Z_EROFS_FRAGMENT_INODE_FLAG, Z_EROFS_LCLUSTER_INDEX_SIZE, Z_EROFS_LCLUSTER_TYPE_HEAD1,
    Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LCLUSTER_TYPE_PLAIN, Z_EROFS_LI_D0_CBLKCNT,
    Z_EROFS_MAP_HEADER_SIZE,
};
use nydus_format::utils::{hex_string, sha256_file};

struct CountingBackend {
    local: Local,
    reads: AtomicUsize,
    fail_next: AtomicBool,
}

fn build_z_reader_fixture(algorithm: ZAlgorithm) -> (TempDir, Vec<u8>) {
    let dir = tempdir().unwrap();
    let source = dir.path().join("src");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("small"), vec![42; 700]).unwrap();
    fs::write(source.join("large"), vec![51; 73 * 4096 + 700]).unwrap();
    let options = BuildImageOptions::new(
        source,
        EROFS_BLOCK_SIZE,
        BlobMetadataCompressor::None,
        HashSet::new(),
        true,
    )
    .unwrap()
    .with_native(NativeLayout::Compressed(algorithm), 0)
    .unwrap();
    let mut blob = Vec::new();
    let image = build_image(&options, &mut blob).unwrap();
    fs::write(dir.path().join(hex_string(&image.full_blob_digest)), blob).unwrap();
    let bootstrap = image.standalone_bootstrap.unwrap();
    fs::write(dir.path().join("bootstrap"), &bootstrap).unwrap();
    (dir, bootstrap)
}

fn z_fixture_nid(reader: &ErofsReader, name: &[u8]) -> u64 {
    let root_nid = reader.superblock().root_nid();
    let root = reader.inode(root_nid).unwrap();
    reader
        .lookup_dir_entry(root_nid, &root, name)
        .unwrap()
        .unwrap()
}

fn z_fixture_tail_offset(reader: &ErofsReader, nid: u64) -> usize {
    let inode = reader.inode(nid).unwrap();
    reader.superblock().meta_blkaddr() as usize * EROFS_BLOCK_SIZE as usize
        + nid as usize * EROFS_SLOTSIZE as usize
        + (inode.header_size() + inode.xattr_size()).div_ceil(8) * 8
}

fn read_z_fixture_range(
    dir: &TempDir,
    bootstrap: &[u8],
    nid: u64,
    offset: u64,
    size: u32,
) -> io::Result<Vec<u8>> {
    let mut file = NamedTempFile::new_in(dir.path())?;
    file.write_all(bootstrap)?;
    let reader = ErofsReader::open_bootstrap(
        file.path(),
        Arc::new(Local::new(dir.path().to_path_buf())),
        None,
        None,
    )?;
    let inode = reader.inode(nid)?;
    let mut output = Vec::new();
    let written = reader.write_file_data_to(nid, &inode, offset, size, &mut output)?;
    assert_eq!(written, output.len());
    Ok(output)
}

#[test]
fn z_reader_rejects_plain_extent_larger_than_physical_block() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, mut bootstrap) = build_z_reader_fixture(algorithm);
        let reader = ErofsReader::open_metadata_only(&dir.path().join("bootstrap")).unwrap();
        let nid = z_fixture_nid(&reader, b"large");
        let index_offset = z_fixture_tail_offset(&reader, nid) + Z_EROFS_MAP_HEADER_SIZE + 8;
        bootstrap[index_offset..index_offset + 2]
            .copy_from_slice(&Z_EROFS_LCLUSTER_TYPE_PLAIN.to_le_bytes());
        let error = read_z_fixture_range(&dir, &bootstrap, nid, 0, 8192).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn z_reader_rejects_head_distance_before_cached_extent() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, mut bootstrap) = build_z_reader_fixture(algorithm);
        let metadata = ErofsReader::open_metadata_only(&dir.path().join("bootstrap")).unwrap();
        let nid = z_fixture_nid(&metadata, b"large");
        let index_offset = z_fixture_tail_offset(&metadata, nid) + Z_EROFS_MAP_HEADER_SIZE + 8;
        let packed_nid = metadata.superblock().packed_nid().unwrap();
        let packed = metadata.inode(packed_nid).unwrap();
        assert_eq!(packed.size(), EROFS_BLOCK_SIZE as u64);
        let packed_tail = metadata.read_z_inode_tail(packed_nid, &packed).unwrap();
        let packed_index =
            &packed_tail[Z_EROFS_MAP_HEADER_SIZE + 8..][..Z_EROFS_LCLUSTER_INDEX_SIZE];
        bootstrap[index_offset..index_offset + 8].copy_from_slice(packed_index);
        bootstrap[index_offset + 8..index_offset + 16].copy_from_slice(packed_index);
        bootstrap[index_offset + 20..index_offset + 22].copy_from_slice(&2u16.to_le_bytes());
        let mut file = NamedTempFile::new_in(dir.path()).unwrap();
        file.write_all(&bootstrap).unwrap();
        let reader = ErofsReader::open_bootstrap(
            file.path(),
            Arc::new(Local::new(dir.path().to_path_buf())),
            None,
            None,
        )
        .unwrap();
        let inode = reader.inode(nid).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            reader
                .write_file_data_to(nid, &inode, 0, 1, &mut output)
                .unwrap(),
            1
        );
        assert_eq!(output, vec![42]);
        for _ in 0..2 {
            assert_eq!(
                reader
                    .write_file_data_to(nid, &inode, 8192, 1, &mut Vec::new())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}

#[test]
fn z_reader_rejects_malformed_indexes_and_packed_nids() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, bootstrap) = build_z_reader_fixture(algorithm);
        let reader = ErofsReader::open_metadata_only(&dir.path().join("bootstrap")).unwrap();
        let nid = z_fixture_nid(&reader, b"large");
        let inode = reader.inode(nid).unwrap();
        let tail_offset = z_fixture_tail_offset(&reader, nid);
        let index_offset = tail_offset + Z_EROFS_MAP_HEADER_SIZE + 8;
        let indexes = reader.read_z_inode_tail(nid, &inode).unwrap();
        let index_end = tail_offset + indexes.len();
        let device = &reader.blob_infos().unwrap()[0];
        let last_block = (device.mapped_blkaddr + device.blocks - 1) as u32;
        let cases: Vec<(&str, usize, Vec<u8>, u64)> = vec![
            (
                "zero head distance",
                index_offset + 12,
                0u16.to_le_bytes().to_vec(),
                4096,
            ),
            (
                "head before start",
                index_offset + 12,
                2u16.to_le_bytes().to_vec(),
                4096,
            ),
            (
                "tail past indexes",
                index_offset + 14,
                u16::MAX.to_le_bytes().to_vec(),
                0,
            ),
            (
                "missing CBLKCNT",
                index_offset + 12,
                1u16.to_le_bytes().to_vec(),
                0,
            ),
            (
                "zero CBLKCNT",
                index_offset + 12,
                Z_EROFS_LI_D0_CBLKCNT.to_le_bytes().to_vec(),
                0,
            ),
            (
                "unsupported head",
                index_offset,
                3u16.to_le_bytes().to_vec(),
                0,
            ),
            (
                "outside device",
                index_offset + 4,
                u32::MAX.to_le_bytes().to_vec(),
                0,
            ),
            (
                "crosses device",
                index_offset + 4,
                last_block.to_le_bytes().to_vec(),
                0,
            ),
        ];
        for (name, position, bytes, offset) in cases {
            let mut malformed = bootstrap.clone();
            malformed[position..position + bytes.len()].copy_from_slice(&bytes);
            if name == "crosses device" {
                malformed[index_offset + 12..index_offset + 14]
                    .copy_from_slice(&(Z_EROFS_LI_D0_CBLKCNT | 2).to_le_bytes());
            }
            assert_eq!(
                read_z_fixture_range(&dir, &malformed, nid, offset, 1)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
                "{algorithm}: {name}"
            );
        }
        assert_eq!(
            read_z_fixture_range(&dir, &bootstrap[..index_end - 1], nid, 0, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            reader
                .read_z_inode_tail(u64::MAX, &inode)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let huge = ErofsInodeExtended::new(
            erofs_extended_i_format(EROFS_INODE_COMPRESSED_FULL),
            0o100644,
            0,
            u64::MAX,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        );
        let huge_inode = ErofsInode::parse(huge.as_bytes()).unwrap();
        assert_eq!(
            reader
                .write_file_data_to(nid, &huge_inode, 0, 1, &mut Vec::new())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let small_nid = z_fixture_nid(&reader, b"small");
        let packed_nid_offset =
            EROFS_SUPER_OFFSET as usize + std::mem::offset_of!(ErofsSuperblock, packed_nid);
        for invalid_nid in [0, u64::MAX, bootstrap.len() as u64] {
            let mut malformed = bootstrap.clone();
            malformed[packed_nid_offset..packed_nid_offset + 8]
                .copy_from_slice(&invalid_nid.to_le_bytes());
            assert_eq!(
                read_z_fixture_range(&dir, &malformed, small_nid, 0, 1)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(read_z_fixture_range(&dir, &bootstrap, nid, 0, 0)
            .unwrap()
            .is_empty());
        assert!(read_z_fixture_range(&dir, &bootstrap, nid, u64::MAX, 1)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn z_reader_validates_whole_file_fragments() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, bootstrap) = build_z_reader_fixture(algorithm);
        let reader = ErofsReader::open_metadata_only(&dir.path().join("bootstrap")).unwrap();
        let nid = z_fixture_nid(&reader, b"small");
        let tail_offset = z_fixture_tail_offset(&reader, nid);
        let packed_nid = reader.superblock().packed_nid().unwrap();
        let packed_size = reader.inode(packed_nid).unwrap().size();
        assert_eq!(
            read_z_fixture_range(&dir, &bootstrap, nid, 0, 700).unwrap(),
            vec![42; 700]
        );
        let mut at_end = bootstrap.clone();
        let fragment_offset = packed_size - 700;
        at_end[tail_offset..tail_offset + 8]
            .copy_from_slice(&(Z_EROFS_FRAGMENT_INODE_FLAG | fragment_offset).to_le_bytes());
        assert_eq!(
            read_z_fixture_range(&dir, &at_end, nid, 0, 700).unwrap(),
            read_z_fixture_range(&dir, &bootstrap, packed_nid, fragment_offset, 700).unwrap()
        );
        assert_eq!(
            read_z_fixture_range(&dir, &bootstrap, nid, 697, 10).unwrap(),
            vec![42; 3]
        );
        for fragment_offset in [
            packed_size - 699,
            packed_size,
            Z_EROFS_FRAGMENT_INODE_FLAG - 1,
        ] {
            let mut malformed = bootstrap.clone();
            malformed[tail_offset..tail_offset + 8]
                .copy_from_slice(&(Z_EROFS_FRAGMENT_INODE_FLAG | fragment_offset).to_le_bytes());
            for offset in [0, 699] {
                assert_eq!(
                    read_z_fixture_range(&dir, &malformed, nid, offset, 1)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidData,
                    "fragment offset {fragment_offset}, read offset {offset}"
                );
            }
        }
        let packed_tail = z_fixture_tail_offset(&reader, packed_nid);
        let mut malformed = bootstrap.clone();
        malformed[packed_tail..packed_tail + 8]
            .copy_from_slice(&Z_EROFS_FRAGMENT_INODE_FLAG.to_le_bytes());
        for target in [nid, packed_nid] {
            assert_eq!(
                read_z_fixture_range(&dir, &malformed, target, 0, 1)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}

#[test]
fn z_reader_validates_tail_fragments_and_packed_recursion() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, bootstrap) = build_z_reader_fixture(algorithm);
        let reader = ErofsReader::open_metadata_only(&dir.path().join("bootstrap")).unwrap();
        let small_nid = z_fixture_nid(&reader, b"small");
        let large_nid = z_fixture_nid(&reader, b"large");
        let packed_nid = reader.superblock().packed_nid().unwrap();
        let packed_size = reader.inode(packed_nid).unwrap().size();
        let large_size = reader.inode(large_nid).unwrap().size();
        let tail_offset = z_fixture_tail_offset(&reader, large_nid);
        let index_offset = tail_offset + Z_EROFS_MAP_HEADER_SIZE + 8;
        let last_cluster = large_size.div_ceil(EROFS_BLOCK_SIZE as u64) as usize - 1;
        let tail_index = index_offset + last_cluster * Z_EROFS_LCLUSTER_INDEX_SIZE;
        let tail_start = last_cluster as u64 * EROFS_BLOCK_SIZE as u64;
        let fragment_len = large_size - tail_start;
        assert!(fragment_len <= 700);
        let make_tail = |fragment_offset: u64| {
            let mut bytes = bootstrap.clone();
            bytes[tail_offset..tail_offset + 4]
                .copy_from_slice(&(fragment_offset as u32).to_le_bytes());
            let advise =
                u16::from_le_bytes(bytes[tail_offset + 4..tail_offset + 6].try_into().unwrap());
            bytes[tail_offset + 4..tail_offset + 6]
                .copy_from_slice(&(advise | Z_EROFS_ADVISE_FRAGMENT_PCLUSTER).to_le_bytes());
            for cluster in 0..last_cluster {
                let entry = index_offset + cluster * Z_EROFS_LCLUSTER_INDEX_SIZE;
                let kind = u16::from_le_bytes(bytes[entry..entry + 2].try_into().unwrap()) & 3;
                if kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                    let delta1 =
                        u16::from_le_bytes(bytes[entry + 6..entry + 8].try_into().unwrap());
                    let distance = usize::from(delta1).min(last_cluster - cluster - 1) as u16;
                    bytes[entry + 6..entry + 8].copy_from_slice(&distance.to_le_bytes());
                }
            }
            bytes[tail_index..tail_index + 2]
                .copy_from_slice(&Z_EROFS_LCLUSTER_TYPE_HEAD1.to_le_bytes());
            bytes[tail_index + 4..tail_index + 8]
                .copy_from_slice(&((fragment_offset >> 32) as u32).to_le_bytes());
            bytes
        };
        for fragment_offset in [0, packed_size - fragment_len] {
            let valid = make_tail(fragment_offset);
            let expected = read_z_fixture_range(
                &dir,
                &bootstrap,
                packed_nid,
                fragment_offset,
                fragment_len as u32,
            )
            .unwrap();
            assert_eq!(
                read_z_fixture_range(&dir, &valid, large_nid, tail_start, u32::MAX).unwrap(),
                expected
            );
        }
        for fragment_offset in [packed_size - fragment_len + 1, packed_size, u64::MAX] {
            let malformed = make_tail(fragment_offset);
            assert_eq!(
                read_z_fixture_range(&dir, &malformed, large_nid, tail_start, 1)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut malformed = bootstrap.clone();
        let packed_tail = z_fixture_tail_offset(&reader, packed_nid);
        let advise = u16::from_le_bytes(
            malformed[packed_tail + 4..packed_tail + 6]
                .try_into()
                .unwrap(),
        );
        malformed[packed_tail + 4..packed_tail + 6]
            .copy_from_slice(&(advise | Z_EROFS_ADVISE_FRAGMENT_PCLUSTER).to_le_bytes());
        for target in [small_nid, packed_nid] {
            assert_eq!(
                read_z_fixture_range(&dir, &malformed, target, 0, 1)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}

#[test]
fn z_compr_cfgs_reads_exact_embedded_offsets() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let (dir, mut bootstrap) = build_z_reader_fixture(algorithm);
        let config = match algorithm {
            ZAlgorithm::Lz4 => ZComprCfgs {
                lz4_max_pclusterblks: Some(7),
                zstd_windowlog: None,
            },
            ZAlgorithm::Zstd => ZComprCfgs {
                lz4_max_pclusterblks: None,
                zstd_windowlog: Some(20),
            },
        };
        let config_offset = EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE;
        let config_bytes = config.to_bytes();
        bootstrap[config_offset..config_offset + config_bytes.len()].copy_from_slice(&config_bytes);
        for offset in [0, 4096, 12288] {
            for compressed in [false, true] {
                let mut region = if compressed {
                    zstd::stream::encode_all(bootstrap.as_slice(), 1).unwrap()
                } else {
                    bootstrap.clone()
                };
                let compressed_size = compressed.then_some(region.len() as u64);
                region.resize(region.len().div_ceil(4096) * 4096, 0);
                let footer = BlobFooter::new(
                    0,
                    offset as u64,
                    offset as u64,
                    (region.len() / 4096) as u32,
                    (offset + region.len()) as u64,
                    1,
                    compressed_size,
                )
                .unwrap();
                let mut blob = vec![0u8; offset];
                blob.extend_from_slice(&region);
                blob.resize(blob.len() + 4096, 0);
                footer.write_to(&mut blob).unwrap();
                let path = dir.path().join(format!("embedded-{offset}-{compressed}"));
                fs::write(&path, blob).unwrap();
                let reader = ErofsReader::open_metadata_only(&path).unwrap();
                assert_eq!(reader.z_compr_cfgs().unwrap(), Some(config));
            }
        }
        if algorithm == ZAlgorithm::Zstd {
            for encoded in [11, 246, u8::MAX] {
                bootstrap[config_offset + 3] = encoded;
                let path = dir.path().join(format!("invalid-config-{encoded}"));
                fs::write(&path, &bootstrap).unwrap();
                let reader = ErofsReader::open_metadata_only(&path).unwrap();
                assert_eq!(
                    reader.z_compr_cfgs().unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }
}

#[test]
fn zstd_config_windowlog_range() {
    use nydus_format::erofs::{
        ZComprCfgs, Z_EROFS_ZSTD_MAX_WINDOWLOG, Z_EROFS_ZSTD_WINDOWLOG_BASE,
    };

    for encoded in 0..=u8::MAX {
        let bytes = [6, 0, 0, encoded, 0, 0, 0, 0];
        let result = ZComprCfgs::parse(1 << ZAlgorithm::Zstd.as_type(), &bytes);
        if encoded <= Z_EROFS_ZSTD_MAX_WINDOWLOG - Z_EROFS_ZSTD_WINDOWLOG_BASE {
            let (config, consumed) = result.unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(
                config.zstd_windowlog,
                Some(encoded + Z_EROFS_ZSTD_WINDOWLOG_BASE)
            );
        } else {
            assert!(
                result.is_err(),
                "accepted zstd windowlog encoding {encoded}"
            );
        }
    }
}

impl BlobBackend for CountingBackend {
    fn blob_metadata(&self, blob_id: &[u8; 32]) -> io::Result<BlobMetadata> {
        self.local.blob_metadata(blob_id)
    }

    fn is_raw_device(&self, blob_id: &[u8; 32]) -> io::Result<bool> {
        self.local.is_raw_device(blob_id)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; 32],
        offset: u64,
        dst: &mut [u8],
        context: ReadContext,
    ) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_next.swap(false, Ordering::Relaxed) {
            return Err(io::Error::other("injected read failure"));
        }
        self.local.read_range_into(blob_id, offset, dst, context)
    }
}

#[test]
fn z_fragments_reuse_decoded_pclusters_across_files_and_threads() {
    for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
        let dir = tempdir().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        let first = vec![b'A'; 16_000];
        let second = vec![b'B'; 16_000];
        let mut random = 17u32;
        let large: Vec<u8> = (0..(5 << 20) + 123)
            .map(|position| {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                if position % 4096 < 1024 {
                    random as u8
                } else {
                    0
                }
            })
            .collect();
        fs::write(source.join("first"), &first).unwrap();
        fs::write(source.join("duplicate"), &first).unwrap();
        fs::set_permissions(
            source.join("duplicate"),
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        fs::write(source.join("second"), &second).unwrap();
        fs::write(source.join("large"), &large).unwrap();
        let options = BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_native(NativeLayout::Compressed(algorithm), 0)
        .unwrap();
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        fs::write(dir.path().join(hex_string(&image.full_blob_digest)), blob).unwrap();
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, image.standalone_bootstrap.unwrap()).unwrap();
        let backend = Arc::new(CountingBackend {
            local: Local::new(dir.path().to_path_buf()),
            reads: AtomicUsize::new(0),
            fail_next: AtomicBool::new(true),
        });
        let reader = ErofsReader::open_bootstrap(&bootstrap, backend.clone(), None, None).unwrap();
        assert!(reader.superblock().packed_nid().is_some());
        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        let first_nid = reader
            .lookup_dir_entry(root_nid, &root, b"first")
            .unwrap()
            .unwrap();
        let second_nid = reader
            .lookup_dir_entry(root_nid, &root, b"second")
            .unwrap()
            .unwrap();
        let inode = reader.inode(first_nid).unwrap();
        let duplicate_nid = reader
            .lookup_dir_entry(root_nid, &root, b"duplicate")
            .unwrap()
            .unwrap();
        assert_ne!(duplicate_nid, first_nid);
        let duplicate_inode = reader.inode(duplicate_nid).unwrap();
        assert_eq!(duplicate_inode.mode() & 0o777, 0o600);
        // Identical small files are packed separately (no fragment dedup),
        // so their fragment offsets differ while sharing the same pcluster.
        assert_ne!(
            reader.read_z_inode_tail(first_nid, &inode).unwrap(),
            reader
                .read_z_inode_tail(duplicate_nid, &duplicate_inode)
                .unwrap()
        );
        let mut output = Vec::new();
        assert!(reader
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .is_err());
        assert!(output.is_empty());
        reader
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .unwrap();
        assert_eq!(output, first);
        let reads = backend.reads.load(Ordering::Relaxed);
        assert!(reads > 0);
        let mut duplicate_output = Vec::new();
        reader
            .write_file_data_to(
                duplicate_nid,
                &duplicate_inode,
                0,
                first.len() as u32,
                &mut duplicate_output,
            )
            .unwrap();
        assert_eq!(duplicate_output, first);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let inode = reader.inode(second_nid).unwrap();
                    let mut output = Vec::new();
                    reader
                        .write_file_data_to(second_nid, &inode, 0, second.len() as u32, &mut output)
                        .unwrap();
                    assert_eq!(output, second);
                })
                .join()
                .unwrap();
        });
        assert_eq!(
            backend.reads.load(Ordering::Relaxed),
            reads,
            "a shared pcluster must not be fetched and decoded again: {algorithm}"
        );
        let large_nid = reader
            .lookup_dir_entry(root_nid, &root, b"large")
            .unwrap()
            .unwrap();
        std::thread::scope(|scope| {
            for offset in [0, 4093, 65_531, 131_069, (4 << 20) - 13, large.len() - 83] {
                let reader = &reader;
                let large = &large;
                scope.spawn(move || {
                    let inode = reader.inode(large_nid).unwrap();
                    let mut output = Vec::new();
                    let written = reader
                        .write_file_data_to(
                            large_nid,
                            &inode,
                            offset as u64,
                            256 << 10,
                            &mut output,
                        )
                        .unwrap();
                    assert_eq!(written, output.len());
                    assert_eq!(
                        &output,
                        &large[offset..(offset + (256 << 10)).min(large.len())]
                    );
                });
            }
        });
        let reads = backend.reads.load(Ordering::Relaxed);
        let other = ErofsReader::open_bootstrap(&bootstrap, backend.clone(), None, None).unwrap();
        let inode = other.inode(first_nid).unwrap();
        let mut output = Vec::new();
        other
            .write_file_data_to(first_nid, &inode, 0, first.len() as u32, &mut output)
            .unwrap();
        assert_eq!(output, first);
        assert!(
            backend.reads.load(Ordering::Relaxed) > reads,
            "each reader owns its cache"
        );
    }
}

/// Native layers carry no blob meta, so there are no chunk groups for an
/// ondemand blob to copy: optimize refuses them with a clear error, while a
/// dense layer is optimized as before and its prefetch fills the source
/// blob's cache.
#[test]
fn optimize_preserves_dense_files_and_refuses_native_layers() {
    use nydus::optimize::{build_ondemand_blob, ChunkGroupRef};

    for algorithm in [None, Some(ZAlgorithm::Lz4), Some(ZAlgorithm::Zstd)] {
        let dir = tempdir().unwrap();
        let source = dir.path().join("src");
        fs::create_dir(&source).unwrap();
        let files = [("small", vec![42; 700]), ("large", vec![51; 300_000])];
        for (name, data) in &files {
            fs::write(source.join(name), data).unwrap();
        }
        let options = BuildImageOptions::new(
            source,
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap();
        let options = match algorithm {
            Some(algorithm) => options
                .with_native(NativeLayout::Compressed(algorithm), 0)
                .unwrap(),
            None => options,
        };
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        fs::write(dir.path().join(hex_string(&image.full_blob_digest)), blob).unwrap();
        let parent = dir.path().join("parent");
        fs::write(&parent, image.standalone_bootstrap.unwrap()).unwrap();
        let backend = Arc::new(Local::new(dir.path().to_path_buf()));
        // Trace every chunk group, last one first.
        let patterns: Vec<ChunkGroupRef> = image
            .blob_metadata
            .as_ref()
            .map(|meta| {
                (0..meta.chunk_group_count() as u32)
                    .rev()
                    .map(|chunk_group_index| ChunkGroupRef {
                        blob_index: 1,
                        chunk_group_index,
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![ChunkGroupRef {
                    blob_index: 1,
                    chunk_group_index: 0,
                }]
            });
        let optimized = build_ondemand_blob(
            &parent,
            &patterns,
            backend.clone(),
            &dir.path().join("build-cache"),
        );
        let optimized = match (algorithm, optimized) {
            (Some(_), Err(err)) => {
                let mut chain = err.to_string();
                let mut source = std::error::Error::source(&err);
                while let Some(cause) = source {
                    chain.push_str(&cause.to_string());
                    source = cause.source();
                }
                assert!(chain.contains("no blob meta"), "{chain}");
                continue;
            }
            (Some(_), Ok(_)) => panic!("optimize must refuse a native layer"),
            (None, result) => result.unwrap(),
        };
        fs::write(
            dir.path().join(hex_string(&optimized.full_blob_digest)),
            &optimized.artifact,
        )
        .unwrap();
        let bootstrap = dir.path().join("optimized");
        fs::write(&bootstrap, &optimized.bootstrap).unwrap();
        let backend = Arc::new(CountingBackend {
            local: Local::new(dir.path().to_path_buf()),
            reads: AtomicUsize::new(0),
            fail_next: AtomicBool::new(false),
        });
        let reader = ErofsReader::open_bootstrap(
            &bootstrap,
            backend.clone(),
            Some(&dir.path().join("read-cache")),
            None,
        )
        .unwrap();
        if let Some(algorithm) = algorithm {
            assert!(reader.z_compr_cfgs().unwrap().unwrap().has(algorithm));
            assert!(reader.superblock().packed_nid().is_some());
        } else {
            assert!(reader.z_compr_cfgs().unwrap().is_none());
        }
        assert_eq!(reader.blob_infos().unwrap().len(), 2);
        assert_eq!(reader.read_prefetch_order()[0], 2);
        reader
            .blob_caches()
            .prefetch_blob(2, 2, std::time::Duration::from_secs(10))
            .unwrap();
        backend.fail_next.store(true, Ordering::Relaxed);
        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        for (name, expected) in &files {
            let nid = reader
                .lookup_dir_entry(root_nid, &root, name.as_bytes())
                .unwrap()
                .unwrap();
            let inode = reader.inode(nid).unwrap();
            let mut data = Vec::new();
            reader
                .write_file_data_to(nid, &inode, 0, expected.len() as u32, &mut data)
                .unwrap();
            assert_eq!(&data, expected, "{algorithm:?}: {name}");
        }
        assert!(
            backend.fail_next.load(Ordering::Relaxed),
            "prefetch must populate the source cache"
        );
    }
}

#[test]
fn optimize_accepts_layers_with_different_chunk_and_group_sizes() {
    use nydus::build::merge::{merge_sources_to_bootstrap_bytes, WhiteoutSpec};
    use nydus::optimize::{build_ondemand_blob, ChunkGroupRef};

    let directory = tempdir().unwrap();
    let files = [
        ("first", vec![42; 4096]),
        ("second", vec![51; 3 * 4096 + 17]),
    ];
    let mut sources = Vec::new();
    let mut metadata = Vec::new();
    let mut encoded = Vec::new();
    for (index, (name, content)) in files.iter().enumerate() {
        let source = directory.path().join(name);
        fs::create_dir(&source).unwrap();
        fs::write(source.join(name), content).unwrap();
        let minimum = (2 << 20) << index;
        let chunk_size = 4096 << index;
        let options = BuildImageOptions::new(
            source,
            chunk_size,
            BlobMetadataCompressor::Zstd,
            HashSet::new(),
            true,
        )
        .unwrap()
        .with_chunk_group_min_size(minimum)
        .unwrap();
        let mut blob = Vec::new();
        let image = build_image(&options, &mut blob).unwrap();
        let meta = image.blob_metadata.unwrap();
        assert_eq!(meta.group_span(), 4 * minimum);
        assert_eq!(meta.chunk_group_count(), 1);
        assert_eq!(
            meta.chunk_count(),
            content.len().div_ceil(chunk_size as usize)
        );
        encoded.push(blob[..meta.compressed_end() as usize].to_vec());
        metadata.push(meta);
        let path = directory.path().join(hex_string(&image.full_blob_digest));
        fs::write(&path, blob).unwrap();
        sources.push(path);
    }
    let parent = directory.path().join("parent");
    fs::write(
        &parent,
        merge_sources_to_bootstrap_bytes(&sources, WhiteoutSpec::Oci).unwrap(),
    )
    .unwrap();
    for order in [[1, 2], [2, 1]] {
        let patterns: Vec<_> = order
            .iter()
            .map(|&blob_index| ChunkGroupRef {
                blob_index,
                chunk_group_index: 0,
            })
            .collect();
        let optimized = build_ondemand_blob(
            &parent,
            &patterns,
            Arc::new(Local::new(directory.path().to_path_buf())),
            &directory.path().join("build-cache"),
        )
        .unwrap();
        let meta = &optimized.blob_metadata;
        assert_eq!(meta.group_span(), 16 << 20);
        assert_eq!(meta.chunk_group_count(), 2);
        let first_span = metadata[usize::from(order[0] - 1)].uncompressed_size();
        assert_eq!(u64::from(meta.lookup_granule()), 1u64 << first_span.ilog2());
        for (index, &source_index) in order.iter().enumerate() {
            let source_meta = &metadata[usize::from(source_index - 1)];
            let group = meta.chunk_group(index).unwrap();
            let range = group.compressed_range();
            assert_eq!(
                &optimized.artifact[range.start as usize..range.end as usize],
                encoded[usize::from(source_index - 1)].as_slice()
            );
            assert_eq!(meta.digest(index), source_meta.digest(0));
            assert_eq!(
                group.chunk_count(),
                source_meta.chunk_group(0).unwrap().chunk_count()
            );
            assert_eq!(group.redirect().unwrap().source_blob_index(), source_index);
            for offset in group.uncompressed_range().step_by(4096) {
                assert_eq!(meta.chunk_group_index_of(offset), Some(index));
            }
        }
        fs::write(
            directory
                .path()
                .join(hex_string(&optimized.full_blob_digest)),
            &optimized.artifact,
        )
        .unwrap();
        let bootstrap = directory.path().join("optimized");
        fs::write(&bootstrap, &optimized.bootstrap).unwrap();
        let backend = Arc::new(CountingBackend {
            local: Local::new(directory.path().to_path_buf()),
            reads: AtomicUsize::new(0),
            fail_next: AtomicBool::new(false),
        });
        let read_cache = directory.path().join(format!("read-cache-{}", order[0]));
        let reader =
            ErofsReader::open_bootstrap(&bootstrap, backend.clone(), Some(&read_cache), None)
                .unwrap();
        reader
            .blob_caches()
            .prefetch_blob(3, 2, std::time::Duration::from_secs(10))
            .unwrap();
        backend.fail_next.store(true, Ordering::Relaxed);
        for (name, content) in &files {
            let nid = z_fixture_nid(&reader, name.as_bytes());
            let inode = reader.inode(nid).unwrap();
            let mut actual = Vec::new();
            reader
                .write_file_data_to(nid, &inode, 0, content.len() as u32, &mut actual)
                .unwrap();
            assert_eq!(&actual, content);
        }
        assert!(backend.fail_next.load(Ordering::Relaxed));
    }
}

#[test]
fn reads_large_xattrs_and_chunk_indexes_after_large_ibody() {
    let file_xattrs: Vec<XattrEntry> = (0..8)
        .map(|index| XattrEntry {
            name_index: EROFS_XATTR_INDEX_USER,
            suffix: format!("large_{index:02}").into_bytes(),
            value: vec![b'A' + index as u8; 700],
        })
        .collect();
    assert!(erofs_xattr_ibody_size(&file_xattrs) > EROFS_BLOCK_SIZE as usize);

    let mut inodes = vec![
        InodeInfo {
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 1_700_000_000,
            mtime_nsec: 0,
            nlink: 2,
            ino: 1,
            nid: 0,
            meta_offset: 0,
            is_extended: true,
            data: InodeData::Directory {
                children: vec![ChildRef {
                    name: "huge_xattrs".into(),
                    file_type: EROFS_FT_REG_FILE,
                    inode_index: 1,
                }],
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
                inline_len: 0,
                inline_tail: Vec::new(),
            },
            xattrs: Vec::new(),
        },
        InodeInfo {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: (EROFS_BLOCK_SIZE as u64) * 2,
            mtime: 1_700_000_123,
            mtime_nsec: 123_456_789,
            nlink: 1,
            ino: 2,
            nid: 0,
            meta_offset: 0,
            is_extended: false,
            data: InodeData::RegularFile {
                chunk_index_entries: vec![
                    ErofsChunkAddr {
                        blkaddr: 11,
                        device_id: 0,
                    },
                    ErofsChunkAddr {
                        blkaddr: 22,
                        device_id: 0,
                    },
                ],
                chunk_size_bits: EROFS_BLKSZBITS as u32,
            },
            xattrs: file_xattrs.clone(),
        },
    ];

    let bootstrap =
        render_bootstrap(&mut inodes, 1_700_000_000, &[], &[0u8; 16]).expect("render bootstrap");
    let mut image = NamedTempFile::new().expect("create temp image");
    image.write_all(&bootstrap).expect("write bootstrap");

    let reader = ErofsReader::open_metadata_only(image.path()).expect("open bootstrap");
    let file_nid = inodes[1].nid;
    let inode = reader.inode(file_nid).expect("read inode");

    let xattrs = reader.read_xattrs(file_nid, &inode).expect("read xattrs");
    assert_eq!(xattrs.len(), file_xattrs.len());
    for ((name, value), expected) in xattrs.iter().zip(file_xattrs.iter()) {
        let expected_name = [b"user.".as_slice(), expected.suffix.as_slice()].concat();
        assert_eq!(name, &expected_name);
        assert_eq!(value, &expected.value);
    }

    let chunk_index_entries = reader
        .read_chunk_index_entries(file_nid, &inode)
        .expect("read chunk indexes");
    assert_eq!(chunk_index_entries.len(), 2);
    assert_eq!(chunk_index_entries[0].blkaddr, 11);
    assert_eq!(chunk_index_entries[0].device_id, 0);
    assert_eq!(chunk_index_entries[1].blkaddr, 22);
    assert_eq!(chunk_index_entries[1].device_id, 0);
}

#[test]
fn reads_chunk_data_from_footer_based_full_blob() {
    let dir = tempdir().expect("create temp dir");
    let source_dir = dir.path().join("src");
    fs::create_dir(&source_dir).expect("create source dir");
    fs::write(source_dir.join("hello.txt"), b"hello nydus\n").expect("write source");

    let data_path = dir.path().join("data.blob");
    let mut blob_writer = BlobWriter::new(
        fs::File::create(&data_path).expect("create blob"),
        EROFS_BLOCK_SIZE,
        BlobMetadataCompressor::None,
        BlobMetadataDigester::Blake3,
        true,
        BlobLayout::ChunkGroups {
            chunk_group_min_size: EROFS_BLOCK_SIZE,
        },
    )
    .expect("blob writer");
    let mut inodes = build_tree(
        &source_dir,
        &mut blob_writer,
        EROFS_BLOCK_SIZE,
        &HashSet::new(),
    )
    .expect("build tree");
    blob_writer.finish().expect("finish blob writer");
    resolve_chunk_addrs(&mut inodes, &blob_writer).expect("resolve chunk addresses");

    let data_blob_id = sha256_file(&data_path).expect("hash data blob");
    let embedded_device_slots =
        [ErofsDeviceSlot::with_blob_id(blob_writer.total_blocks(), &data_blob_id).unwrap()];
    let embedded_bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        &embedded_device_slots,
        &[0u8; 16],
    )
    .expect("render embedded bootstrap");
    let blob_metadata = blob_writer.blob_metadata().expect("blob meta");

    let data = fs::read(&data_path).expect("read data blob");
    let full_blob_digest =
        fixture::assemble_full_blob(dir.path(), &data, &embedded_bootstrap, &blob_metadata);

    let standalone_device_slots =
        [ErofsDeviceSlot::with_blob_id(blob_writer.total_blocks(), &full_blob_digest).unwrap()];
    let bootstrap = render_bootstrap(
        &mut inodes,
        1_700_000_000,
        &standalone_device_slots,
        &[0u8; 16],
    )
    .expect("render standalone bootstrap");

    let bootstrap_path = dir.path().join("bootstrap");
    fs::write(&bootstrap_path, &bootstrap).expect("write bootstrap file");

    let backend: std::sync::Arc<dyn nydus_backend::BlobBackend> =
        std::sync::Arc::new(nydus_backend::Local::new(dir.path().to_path_buf()));
    let reader =
        ErofsReader::open_bootstrap(&bootstrap_path, backend, None, None).expect("open reader");
    let root = reader
        .inode(reader.superblock().root_nid())
        .expect("root inode");
    let entries = reader
        .read_dir(reader.superblock().root_nid(), &root)
        .expect("read root dir");
    let file_nid = entries
        .iter()
        .find(|entry| entry.name == b"hello.txt")
        .expect("hello entry")
        .nid;
    let inode = reader.inode(file_nid).expect("file inode");
    let data = reader
        .read_file_data(file_nid, &inode, 0, inode.size() as u32)
        .expect("read file data");

    assert_eq!(data, b"hello nydus\n");
}
