//! Immutable device geometry. Building and walking a layout never opens a cache.

use nydus_error::{Error, Result};
use nydus_format::erofs::EROFS_BLOCK_SIZE;

use crate::extent::{clamped_range_end, BlobRangeSpec};
use crate::reader::RawBlobInfo;

pub(crate) struct BlobRegion {
    pub index: u16,
    pub start: u64,
    pub end: u64,
}

pub(crate) struct FlatLayout {
    blobs: Vec<BlobRegion>,
    bootstrap_size: u64,
    size: u64,
}

impl FlatLayout {
    pub(crate) fn new(bootstrap_size: u64, infos: &[RawBlobInfo]) -> Result<Self> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        let mut size = bootstrap_size;
        let mut blobs = Vec::with_capacity(infos.len());
        for info in infos {
            let start = info
                .mapped_blkaddr
                .checked_mul(block_size)
                .ok_or_else(|| Error::Overflow("mapped blob offset overflow".to_string()))?;
            let len = info
                .blocks
                .checked_mul(block_size)
                .ok_or_else(|| Error::Overflow("blob size overflow".to_string()))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| Error::Overflow("flat blob range overflow".to_string()))?;
            size = size.max(end);
            blobs.push(BlobRegion {
                index: info.blob_index,
                start,
                end,
            });
        }
        blobs.sort_by_key(|blob| blob.start);
        Ok(Self {
            blobs,
            bootstrap_size,
            size,
        })
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn segments(&self, offset: u64, len: u64) -> Result<Segments<'_>> {
        let end = clamped_range_end(offset, len, self.size)?.unwrap_or(offset);
        Ok(Segments {
            layout: self,
            pos: offset,
            end,
        })
    }
}

pub(crate) enum Segment {
    Bootstrap { offset: u64, len: u64 },
    Zero { offset: u64, len: u64 },
    Blob { range: BlobRangeSpec },
}

#[derive(Clone)]
pub(crate) struct Segments<'a> {
    layout: &'a FlatLayout,
    pos: u64,
    end: u64,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.end {
            return None;
        }
        let start = self.pos;
        if start < self.layout.bootstrap_size {
            self.pos = self.end.min(self.layout.bootstrap_size);
            return Some(Segment::Bootstrap {
                offset: start,
                len: self.pos - start,
            });
        }
        let blobs = &self.layout.blobs;
        let after = blobs.partition_point(|blob| blob.start <= start);
        if let Some(slot) = after.checked_sub(1) {
            let blob = &blobs[slot];
            if start < blob.end {
                self.pos = self.end.min(blob.end);
                return Some(Segment::Blob {
                    range: BlobRangeSpec {
                        index: blob.index,
                        offset: start - blob.start,
                        len: self.pos - start,
                        source_offset: start,
                    },
                });
            }
        }
        self.pos = self
            .end
            .min(blobs.get(after).map(|blob| blob.start).unwrap_or(self.end));
        Some(Segment::Zero {
            offset: start,
            len: self.pos - start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(index: u16, start: u64, blocks: u64) -> RawBlobInfo {
        RawBlobInfo {
            blob_index: index,
            blob_id: [0; 32],
            blocks,
            mapped_blkaddr: start,
        }
    }

    #[test]
    fn walks_unsorted_devices_and_holes_without_cache_preparation() {
        let layout = FlatLayout::new(4096, &[blob(2, 4, 2), blob(1, 2, 1)]).unwrap();
        let segments: Vec<_> = layout.segments(2048, u32::MAX as u64).unwrap().collect();
        assert_eq!(segments.len(), 5);
        assert!(matches!(
            segments[0],
            Segment::Bootstrap {
                offset: 2048,
                len: 2048
            }
        ));
        assert!(matches!(
            segments[1],
            Segment::Zero {
                offset: 4096,
                len: 4096
            }
        ));
        assert!(matches!(
            segments[2],
            Segment::Blob {
                range: BlobRangeSpec {
                    index: 1,
                    offset: 0,
                    len: 4096,
                    source_offset: 8192,
                }
            }
        ));
        assert!(matches!(
            segments[3],
            Segment::Zero {
                offset: 12288,
                len: 4096
            }
        ));
        assert!(matches!(
            segments[4],
            Segment::Blob {
                range: BlobRangeSpec {
                    index: 2,
                    offset: 0,
                    len: 8192,
                    source_offset: 16384,
                }
            }
        ));
        assert_eq!(layout.size(), 24576);
        let partial: Vec<_> = layout.segments(18000, 1000).unwrap().collect();
        assert!(matches!(
            partial.as_slice(),
            [Segment::Blob {
                range: BlobRangeSpec {
                    index: 2,
                    offset: 1616,
                    len: 1000,
                    source_offset: 18000,
                },
                ..
            }]
        ));
    }

    #[test]
    fn bounds_empty_requests_and_rejects_overflow() {
        let layout = FlatLayout::new(4096, &[]).unwrap();
        assert_eq!(layout.segments(4096, 1).unwrap().count(), 0);
        assert_eq!(layout.segments(0, 0).unwrap().count(), 0);
        assert!(layout.segments(u64::MAX, 2).is_err());
        assert!(FlatLayout::new(4096, &[blob(1, u64::MAX, 1)]).is_err());
        assert!(FlatLayout::new(4096, &[blob(1, 1, u64::MAX)]).is_err());
    }
}
