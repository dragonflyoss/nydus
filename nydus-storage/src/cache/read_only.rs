//! Opportunistic decoded reads from another process's cache, never written here.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use nydus_format::blob::BlobMetadata;

use super::cached_chunk_group_is_intact;
use crate::chunk_group_map::ReadOnlyChunkGroupMap;

/// A borrowed cache family. Open descriptors survive snapshotter GC unlink;
/// each ready group is verified before use, including races opening the family.
/// Never changes the source files.
struct ReadOnlyBlobCache {
    data: File,
    map: ReadOnlyChunkGroupMap,
    metadata: BlobMetadata,
}

impl ReadOnlyBlobCache {
    /// Open an existing digest-named decoded cache family. Missing or invalid
    /// families are errors; callers may treat them as misses and use a backend.
    fn open(dir: &Path, digest: &[u8; 32]) -> io::Result<Self> {
        let id = hex::encode(digest);
        // Data first: GC unlinks it before its sidecars. Holding the fd avoids
        // reopening a replacement sparse data file under an older ready map.
        let data = File::open(dir.join(format!("{id}.blob.data")))?;
        let metadata = BlobMetadata::from_path(&dir.join(format!("{id}.blob.meta")))
            .map_err(io::Error::other)?;
        let map = ReadOnlyChunkGroupMap::open(
            &dir.join(format!("{id}.group.map")),
            metadata.chunk_group_count(),
        )?;
        Ok(Self {
            data,
            map,
            metadata,
        })
    }
}

/// Optional read-only decoded sources for a repack job. Missing families fall
/// back to the normal reader. Only one padded group is buffered across blobs.
pub struct ReadOnlyBlobCaches {
    dir: PathBuf,
    blobs: HashMap<[u8; 32], Option<ReadOnlyBlobCache>>,
    group: Option<([u8; 32], usize)>,
    bytes: Vec<u8>,
}

impl ReadOnlyBlobCaches {
    /// Borrow existing cache families lazily; construction performs no I/O.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            blobs: HashMap::new(),
            group: None,
            bytes: Vec::new(),
        }
    }

    /// Read decoded bytes, delegating only missing or invalid groups to
    /// `fallback`. The fallback must overwrite its entire destination slice.
    pub fn read_at(
        &mut self,
        digest: [u8; 32],
        mut offset: u64,
        mut dst: &mut [u8],
        mut fallback: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if dst.is_empty() {
            return Ok(());
        }
        offset
            .checked_add(dst.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache range overflow"))?;
        let Some(cache) = self
            .blobs
            .entry(digest)
            .or_insert_with(|| ReadOnlyBlobCache::open(&self.dir, &digest).ok())
        else {
            return fallback(offset, dst);
        };
        while !dst.is_empty() {
            let Some(index) = cache.metadata.chunk_group_index(offset) else {
                return fallback(offset, dst);
            };
            let group = cache
                .metadata
                .chunk_group(index)
                .expect("validated group index");
            let start = group.logical_offset();
            let available =
                usize::try_from(start + group.logical_size() - offset).map_err(io::Error::other)?;
            let len = dst.len().min(available);
            if len == 0 {
                return fallback(offset, dst);
            }
            let (head, tail) = dst.split_at_mut(len);
            if self.group == Some((digest, index)) {
                let at = (offset - start) as usize;
                head.copy_from_slice(&self.bytes[at..at + len]);
            } else {
                self.group = None;
                if cache.map.is_ready(index).unwrap_or(false) {
                    let read_group = |span: &mut [u8]| {
                        cache.data.read_exact_at(span, start).is_ok()
                            && cached_chunk_group_is_intact(&cache.metadata, &group, span)
                    };
                    if offset == start && len as u64 == group.logical_size() {
                        // A complete group already fits the encoder's source
                        // buffer: read and verify it in place, with no copy.
                        if !read_group(head) {
                            fallback(offset, head)?;
                        }
                    } else {
                        let size =
                            usize::try_from(group.logical_size()).map_err(io::Error::other)?;
                        self.bytes.resize(size, 0);
                        if read_group(&mut self.bytes) {
                            self.group = Some((digest, index));
                            let at = (offset - start) as usize;
                            head.copy_from_slice(&self.bytes[at..at + len]);
                        } else {
                            fallback(offset, head)?;
                        }
                    }
                } else {
                    fallback(offset, head)?;
                }
            }
            offset += len as u64;
            dst = tail;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_group_map::{current_boot_tag, ChunkGroupMap};
    use nydus_format::blob::{BlobMetadataCompressor, BlobMetadataDigester};
    use nydus_test_utils::metadata::from_chunk_groups;

    const ID: [u8; 32] = [0x42; 32];

    fn family(dir: &Path, ready: usize) -> (Vec<u8>, ChunkGroupMap) {
        let (_, metadata) = from_chunk_groups(
            BlobMetadataCompressor::Zstd,
            16384,
            &[vec![vec![1; 100], vec![2; 5000]], vec![vec![3; 4096]]],
            Some(BlobMetadataDigester::Blake3),
        );
        let id = hex::encode(ID);
        metadata.save(&dir.join(format!("{id}.blob.meta"))).unwrap();
        let data = File::create(dir.join(format!("{id}.blob.data"))).unwrap();
        let mut expected = vec![0; metadata.logical_size() as usize];
        expected[..100].fill(1);
        expected[4096..9096].fill(2);
        expected[12288..16384].fill(3);
        data.write_all_at(&expected, 0).unwrap();
        let map = ChunkGroupMap::open(&dir.join(format!("{id}.group.map")), 2).unwrap();
        if let Some(tag) = current_boot_tag() {
            map.set_boot_tag(tag);
        }
        map.set_range_ready(0..ready).unwrap();
        (expected, map)
    }

    #[test]
    fn only_ready_valid_groups_are_borrowed_without_source_writes() {
        for ready in 0..=2 {
            let dir = tempfile::tempdir().unwrap();
            let (expected, _map) = family(dir.path(), ready);
            let paths = [".blob.data", ".blob.meta", ".group.map"]
                .map(|suffix| dir.path().join(format!("{}{suffix}", hex::encode(ID))));
            let before = paths.each_ref().map(|p| std::fs::read(p).unwrap());
            let mut caches = ReadOnlyBlobCaches::new(dir.path().to_path_buf());
            let mut actual = vec![0; expected.len()];
            let mut fetched = 0;
            caches
                .read_at(ID, 0, &mut actual, |offset, dst| {
                    assert!(offset >= if ready == 0 { 0 } else { 12288 });
                    fetched += dst.len();
                    dst.copy_from_slice(&expected[offset as usize..offset as usize + dst.len()]);
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(fetched, [16384, 4096, 0][ready]);
            assert_eq!(
                caches.bytes.capacity(),
                0,
                "whole groups need no intermediate buffer"
            );
            for (path, bytes) in paths.iter().zip(before) {
                assert_eq!(std::fs::read(path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn partial_groups_reuse_one_buffer_and_empty_reads_do_no_io() {
        let dir = tempfile::tempdir().unwrap();
        let mut caches = ReadOnlyBlobCaches::new(dir.path().to_path_buf());
        caches
            .read_at(ID, u64::MAX, &mut [], |_, _| panic!("empty fallback"))
            .unwrap();
        assert!(caches.blobs.is_empty());
        let (expected, _map) = family(dir.path(), 2);
        let mut actual = vec![0; 6000];
        caches
            .read_at(ID, 50, &mut actual, |_, _| {
                panic!("warm partial group fetched")
            })
            .unwrap();
        assert_eq!(actual, expected[50..6050]);
        let capacity = caches.bytes.capacity();
        caches
            .read_at(ID, 12200, &mut actual, |offset, dst| {
                // The request extends past the blob; preserve the fallback's error.
                assert_eq!(offset, expected.len() as u64);
                dst.fill(0);
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "past blob"))
            })
            .unwrap_err();
        assert_eq!(&actual[..4184], &expected[12200..]);
        assert_eq!(caches.bytes.capacity(), capacity);
    }

    #[test]
    fn invalid_or_missing_cache_falls_back_and_open_fds_survive_gc() {
        for mode in [
            "missing",
            "stale-boot",
            "truncated-map",
            "corrupt-data",
            "gc",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (expected, map) = family(dir.path(), 2);
            let prefix = dir.path().join(hex::encode(ID));
            let path = |suffix| PathBuf::from(format!("{}{suffix}", prefix.display()));
            match mode {
                "missing" => std::fs::remove_file(path(".blob.data")).unwrap(),
                "stale-boot" => map.set_boot_tag(0),
                "truncated-map" => File::create(path(".group.map"))
                    .unwrap()
                    .set_len(10)
                    .unwrap(),
                "corrupt-data" => File::create(path(".blob.data"))
                    .unwrap()
                    .set_len(expected.len() as u64)
                    .unwrap(),
                _ => {}
            }
            let mut caches = ReadOnlyBlobCaches::new(dir.path().to_path_buf());
            if mode == "gc" {
                caches
                    .read_at(ID, 0, &mut [0; 100], |_, _| panic!("warm group fetched"))
                    .unwrap();
                for suffix in [".blob.data", ".blob.meta", ".group.map"] {
                    std::fs::remove_file(path(suffix)).unwrap();
                }
                // A replacement sparse cache must not replace the opened fd.
                File::create(path(".blob.data"))
                    .unwrap()
                    .set_len(expected.len() as u64)
                    .unwrap();
            }
            let mut actual = vec![0; expected.len()];
            let mut fetched = 0;
            caches
                .read_at(ID, 0, &mut actual, |offset, dst| {
                    fetched += dst.len();
                    dst.copy_from_slice(&expected[offset as usize..offset as usize + dst.len()]);
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual, expected, "{mode}");
            assert_eq!(
                fetched,
                if mode == "gc" { 0 } else { expected.len() },
                "{mode}"
            );
        }
    }
}
