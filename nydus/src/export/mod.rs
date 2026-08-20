//! Turn a nydus image back into an uncompressed OCI layer tar stream.
//!
//! A nydus layer blob is self-describing — `[data | bootstrap | blob meta |
//! footer]` — so a single blob file carries both the filesystem tree and the
//! chunk data of exactly one OCI layer. Walking that tree and emitting a tar
//! entry per inode reproduces the layer without consulting a merged bootstrap
//! or any lower layer.
//!
//! OCI whiteouts need no special handling: the conversion extracts `.wh.*`
//! markers verbatim into the source tree, so they are ordinary inodes here and
//! round-trip as ordinary tar entries.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use nydus_error::{Context, Error, Result};
use tar::{Builder, EntryType, Header};

use nydus_core::ErofsReader;
use nydus_format::erofs::{
    is_nydus_xattr, mode_to_erofs_file_type, ErofsInode, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV,
    EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
};

/// Guards against unbounded recursion on a corrupted or hostile image.
const MAX_DEPTH: u32 = 1024;

/// Write the whole filesystem tree of `reader` as an uncompressed tar stream.
pub fn write_tar<W: Write>(reader: &ErofsReader, writer: W) -> Result<()> {
    let sb = reader.superblock();
    let mut ctx = Unpacker {
        reader,
        epoch: sb.epoch(),
        fixed_nsec: sb.fixed_nsec(),
        hardlinks: HashMap::new(),
    };
    let mut builder = Builder::new(writer);
    ctx.walk_dir(&mut builder, sb.root_nid(), &[], 0)?;
    builder.into_inner()?.flush()?;
    Ok(())
}

struct Unpacker<'a> {
    reader: &'a ErofsReader,
    epoch: u64,
    fixed_nsec: u32,
    hardlinks: HashMap<u64, PathBuf>,
}

impl Unpacker<'_> {
    fn walk_dir<W: Write>(
        &mut self,
        builder: &mut Builder<W>,
        nid: u64,
        prefix: &[u8],
        depth: u32,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::InvalidImage(format!(
                "directory nesting exceeds {MAX_DEPTH} levels at inode {nid}"
            )));
        }
        let inode = self
            .reader
            .inode(nid)
            .with_context(|| format!("failed to read inode: {nid}"))?;
        let entries = self
            .reader
            .read_dir(nid, &inode)
            .with_context(|| format!("failed to read directory inode: {nid}"))?;

        for entry in entries {
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            let mut path = prefix.to_vec();
            path.extend_from_slice(&entry.name);
            let display = String::from_utf8_lossy(&path).into_owned();

            let is_dir = self
                .append_entry(builder, entry.nid, &path)
                .with_context(|| format!("failed to pack entry: {display}"))?;
            if is_dir {
                path.push(b'/');
                self.walk_dir(builder, entry.nid, &path, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Append one inode as a tar entry, returning whether it is a directory.
    fn append_entry<W: Write>(
        &mut self,
        builder: &mut Builder<W>,
        nid: u64,
        path: &[u8],
    ) -> Result<bool> {
        let inode = self.reader.inode(nid)?;
        let file_type = mode_to_erofs_file_type(inode.mode());

        // Sockets cannot be represented in tar; container tooling drops them too.
        if file_type == EROFS_FT_SOCK {
            tracing::warn!("skipping socket {}", String::from_utf8_lossy(path));
            return Ok(false);
        }

        let mut header = Header::new_gnu();
        header.set_mode(inode.mode() as u32 & 0o7777);
        header.set_uid(inode.uid() as u64);
        header.set_gid(inode.gid() as u64);
        let mtime = inode.mtime(self.epoch);
        header.set_mtime(mtime);
        header.set_size(0);

        let mut tar_path = path.to_vec();
        let mut link_target = None;
        match file_type {
            EROFS_FT_DIR => {
                header.set_entry_type(EntryType::Directory);
                tar_path.push(b'/');
            }
            EROFS_FT_REG_FILE => match self.hardlinks.get(&nid) {
                Some(target) => {
                    header.set_entry_type(EntryType::Link);
                    link_target = Some(target.clone());
                }
                None => {
                    header.set_entry_type(EntryType::Regular);
                    header.set_size(inode.size());
                    if inode.nlink() > 1 {
                        self.hardlinks.insert(nid, bytes_to_path(path));
                    }
                }
            },
            EROFS_FT_SYMLINK => {
                header.set_entry_type(EntryType::Symlink);
                let target = self.reader.read_symlink(nid, &inode)?;
                link_target = Some(bytes_to_path(&target));
            }
            EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => {
                header.set_entry_type(if file_type == EROFS_FT_CHRDEV {
                    EntryType::Char
                } else {
                    EntryType::Block
                });
                let (major, minor) = decode_rdev(inode.rdev());
                header.set_device_major(major)?;
                header.set_device_minor(minor)?;
            }
            EROFS_FT_FIFO => header.set_entry_type(EntryType::Fifo),
            other => {
                return Err(Error::Unsupported(format!(
                    "unsupported inode file type {other}"
                )))
            }
        }

        let pax = self.pax_records(nid, &inode, mtime)?;
        if !pax.is_empty() {
            builder.append_pax_extensions(pax.iter().map(|(k, v)| (k.as_str(), v.as_slice())))?;
        }

        let tar_path = bytes_to_path(&tar_path);
        // append_link rather than set_link_name: a ustar header only has room
        // for a 100-byte target, and a symlink target can run to PATH_MAX.
        if let Some(target) = link_target {
            builder.append_link(&mut header, tar_path, target)?;
        } else if header.entry_type() == EntryType::Regular {
            builder.append_data(&mut header, tar_path, InodeReader::new(self.reader, nid)?)?;
        } else {
            builder.append_data(&mut header, tar_path, io::empty())?;
        }

        Ok(file_type == EROFS_FT_DIR)
    }

    /// Collect PAX records for xattrs and sub-second mtime, dropping the
    /// `trusted.nydus.*` xattrs that only exist to drive the nydus runtime.
    fn pax_records(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        mtime: u64,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut records = Vec::new();
        for (name, value) in self.reader.read_xattrs(nid, inode)? {
            if is_nydus_xattr(&name) {
                continue;
            }
            match String::from_utf8(name) {
                Ok(name) => records.push((format!("SCHILY.xattr.{name}"), value)),
                Err(err) => tracing::warn!(
                    "skipping non-UTF-8 xattr on inode {nid}: {}",
                    String::from_utf8_lossy(err.as_bytes())
                ),
            }
        }
        let nsec = inode.effective_mtime_nsec(self.fixed_nsec);
        if nsec != 0 {
            records.push((
                "mtime".to_string(),
                format!("{mtime}.{nsec:09}").into_bytes(),
            ));
        }
        Ok(records)
    }
}

/// Pull-based adapter over the push-based `write_file_data_to`, so that file
/// data streams into the tar writer without buffering the whole file.
struct InodeReader<'a> {
    reader: &'a ErofsReader,
    inode: ErofsInode<'a>,
    nid: u64,
    pos: u64,
    size: u64,
}

impl<'a> InodeReader<'a> {
    fn new(reader: &'a ErofsReader, nid: u64) -> Result<Self> {
        let inode = reader.inode(nid)?;
        let size = inode.size();
        Ok(Self {
            reader,
            inode,
            nid,
            pos: 0,
            size,
        })
    }
}

impl Read for InodeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.size.saturating_sub(self.pos);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = remaining.min(buf.len() as u64).min(u32::MAX as u64) as u32;
        let mut out = &mut buf[..want as usize];
        let read =
            self.reader
                .write_file_data_to(self.nid, &self.inode, self.pos, want, &mut out)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("inode {} returned no data at offset {}", self.nid, self.pos),
            ));
        }
        self.pos += read as u64;
        Ok(read)
    }
}

fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

/// Split a Linux 32-bit encoded `dev_t` into its major and minor numbers.
fn decode_rdev(rdev: u32) -> (u32, u32) {
    let major = (rdev >> 8) & 0xfff;
    let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
    (major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rdev_matches_linux_encoding() {
        // /dev/null is 1:3, /dev/sda is 8:0.
        assert_eq!(decode_rdev((1 << 8) | 3), (1, 3));
        assert_eq!(decode_rdev(8 << 8), (8, 0));
        // A minor above 255 spills into the high bits.
        assert_eq!(
            decode_rdev((136 << 8) | (1 << 12 << 8) | 0x22),
            (136, 0x122)
        );
    }
}
