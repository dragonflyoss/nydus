//! Layer tar normalization: reads a layer tar the way Go's `archive/tar`
//! does and resolves each member the way containerd's `archive.Apply`
//! lands it, so [`super::tar`] renders the tree Apply would create.
//!
//! The reader parses every header format Go does: USTAR, PAX (records are
//! length-prefixed, so values may hold newlines), GNU long names, base-256
//! numbers and all GNU sparse encodings, whose holes read back as zeros.
//! The tar crate cannot stand in for it: it splits PAX records at newlines
//! and reads no PAX sparse map.
//!
//! Member paths are then resolved within the root through the symlinks
//! earlier members made, following continuity's `fs.RootPath`, and members
//! Go or Apply reject fail the layer. A single layer departs from Apply in
//! that GNU sparse and contiguous members are the regular files Go reads
//! them as, dumpdir members are directories, and OCI whiteouts are kept as
//! plain files for `merge` to interpret.

use nydus_error::{Context, Error, Result};
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::rc::Rc;

const BLOCK: usize = 512;

// Type flags.
const REGA: u8 = 0;
const REG: u8 = b'0';
const LINK: u8 = b'1';
const SYMLINK: u8 = b'2';
const CHAR: u8 = b'3';
const BLOCK_DEV: u8 = b'4';
const DIR: u8 = b'5';
const FIFO: u8 = b'6';
const CONT: u8 = b'7';
const XHEADER: u8 = b'x';
const XGLOBAL: u8 = b'g';
const GNU_SPARSE: u8 = b'S';
const GNU_LONGNAME: u8 = b'L';
const GNU_LONGLINK: u8 = b'K';
/// GNU's incremental directory entry, which Go reads but does not name.
const GNU_DUMPDIR: u8 = b'D';

/// Go's bound on the body of a PAX header or GNU long name.
const MAX_SPECIAL_FILE: u64 = 1 << 20;

/// Linux PATH_MAX and NAME_MAX.
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;

/// Bounds symlink resolution as continuity's `fs.RootPath` does.
const MAX_LINKS_WALKED: usize = 255;

/// The kernel's MAXSYMLINKS: lstat(2) fails with ELOOP after following that
/// many symlinks within one path.
const MAX_LINKS_FOLLOWED: usize = 40;

/// Linux XATTR_NAME_MAX and XATTR_SIZE_MAX.
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;

/// The latest time Apply's `os.Chtimes` can set: `time.Unix(0, MaxInt64)`.
const MAX_TIME: (i64, u32) = (9_223_372_036, 854_775_807);

/// Full xattr names and their values.
pub(super) type Xattrs = BTreeMap<Vec<u8>, Vec<u8>>;

/// A member as Apply lands it.
pub(super) struct Member {
    /// Path components below the root, resolved; never empty.
    pub path: Vec<Vec<u8>>,
    pub kind: Kind,
    /// Permission bits.
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub xattrs: Xattrs,
}

pub(super) enum Kind {
    Dir,
    /// A regular file of this size, whose data is passed along.
    Reg(u64),
    Symlink(Vec<u8>),
    /// A hard link to the inode at these resolved path components.
    Link(Vec<Vec<u8>>),
    Char(u32),
    Block(u32),
    Fifo,
    /// Apply's last pass sets the mtime of each directory member again,
    /// resolving its name through the finished tree: only the member's
    /// mtime applies, to whatever inode is at its path.
    Restamp,
}

/// Normalizes the layer tar read from `r`, calling `apply` for each member
/// in order with its data, which is empty but for a regular file.
pub(super) fn normalize<R: Read>(
    r: R,
    mut apply: impl FnMut(Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut tr = TarReader::new(r);
    let mut tree = Tree::new();
    let mut dirs = Vec::new();
    while let Some(hdr) = tr.next().context("failed to read layer tar")? {
        let members = tree
            .apply(&hdr)
            .with_context(|| format!("layer tar member {}", show(&hdr.name)))?;
        // Of a global header, only the directories it implied are emitted.
        let own = (hdr.typeflag != XGLOBAL).then(|| members.len().wrapping_sub(1));
        for (i, member) in members.into_iter().enumerate() {
            if Some(i) == own && matches!(member.kind, Kind::Dir) {
                dirs.push((clean(&hdr.name), (member.mtime, member.mtime_nsec)));
            }
            if let Kind::Reg(_) = member.kind {
                apply(member, &mut tr)?;
                // Reading what is left checks a sparse map against the data
                // the member holds.
                io::copy(&mut tr, &mut io::sink())
                    .with_context(|| format!("layer tar member {}", show(&hdr.name)))?;
            } else {
                apply(member, &mut io::empty())?;
            }
        }
    }
    if let Some(p) = tree.removed.keys().next() {
        return Err(invalid(format!(
            "global header removes {}, which no later member replaces",
            show(p)
        )));
    }
    for member in tree.restamp_dirs(dirs)? {
        apply(member, &mut io::empty())?;
    }
    // Whatever follows the end-of-archive marker is ignored, but draining a
    // gzip stream to its end verifies its checksum, as containerd does.
    io::copy(&mut tr.r, &mut io::sink()).context("failed to drain layer tar")?;
    Ok(())
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidParameter(msg.into())
}

fn bad_header() -> Error {
    invalid("invalid tar header")
}

fn unexpected_eof() -> Error {
    io::Error::from(io::ErrorKind::UnexpectedEof).into()
}

fn sparse_too_long() -> Error {
    invalid("sparse map too long")
}

fn show(p: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(p))
}

/// A member header as Go's `tar.Reader.Next` returns it.
#[derive(Default)]
struct Header {
    typeflag: u8,
    name: Vec<u8>,
    linkname: Vec<u8>,
    size: i64,
    mode: i64,
    uid: i64,
    gid: i64,
    mtime: (i64, u32),
    devmajor: i64,
    devminor: i64,
    pax: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    V7,
    Ustar,
    Star,
    Gnu,
}

/// A port of Go's `archive/tar` reader. As a [`Read`], it yields the
/// logical data of the current member.
struct TarReader<R> {
    r: R,
    /// Bytes of the current member's data section not read yet.
    remaining: u64,
    /// Padding after the current member's data section.
    pad: usize,
    sparse: Option<Sparse>,
}

/// The read state of a sparse member: its data fragments, as (offset,
/// length) pairs in order, and the logical position and size.
struct Sparse {
    frags: Vec<(u64, u64)>,
    idx: usize,
    pos: u64,
    size: u64,
}

impl<R: Read> TarReader<R> {
    fn new(r: R) -> Self {
        TarReader {
            r,
            remaining: 0,
            pad: 0,
            sparse: None,
        }
    }

    /// Returns the next member, or `None` at the end of the archive.
    fn next(&mut self) -> Result<Option<Header>> {
        let mut pax = None;
        let (mut long_name, mut long_link) = (Vec::new(), Vec::new());
        loop {
            // Skip the rest of the previous member and its padding. Like
            // Go, a stream that ends within the padding ends the archive.
            let left = self.remaining;
            if io::copy(&mut (&mut self.r).take(left), &mut io::sink())? < left {
                return Err(unexpected_eof());
            }
            let mut pad = [0u8; BLOCK];
            if read_full(&mut self.r, &mut pad[..self.pad])? < self.pad {
                return Ok(None);
            }
            (self.remaining, self.pad, self.sparse) = (0, 0, None);

            let mut blk = [0u8; BLOCK];
            if !self.read_block(&mut blk)? {
                return Ok(None);
            }
            if blk == [0; BLOCK] {
                if !self.read_block(&mut blk)? || blk == [0; BLOCK] {
                    return Ok(None);
                }
                return Err(bad_header());
            }
            let mut hdr = parse_header(&blk)?;
            self.set_body(&hdr)?;
            match hdr.typeflag {
                XHEADER | XGLOBAL => {
                    let records = parse_pax(&self.read_special()?)?;
                    if hdr.typeflag == XGLOBAL {
                        // Go ignores what a global header's records fail.
                        let _ = merge_pax(&mut hdr, records);
                        return Ok(Some(hdr));
                    }
                    pax = Some(records);
                }
                GNU_LONGNAME => long_name = cut_nul(&self.read_special()?).to_vec(),
                GNU_LONGLINK => long_link = cut_nul(&self.read_special()?).to_vec(),
                _ => {
                    if let Some(records) = pax.take() {
                        merge_pax(&mut hdr, records)?;
                    }
                    if !long_name.is_empty() {
                        hdr.name = long_name;
                    }
                    if !long_link.is_empty() {
                        hdr.linkname = long_link;
                    }
                    if hdr.typeflag == REGA {
                        // Legacy archives mark directories with a slash.
                        hdr.typeflag = if hdr.name.ends_with(b"/") { DIR } else { REG };
                    }
                    // PAX records may have changed the size.
                    self.set_body(&hdr)?;
                    self.read_sparse_map(&mut hdr, &blk)?;
                    return Ok(Some(hdr));
                }
            }
        }
    }

    /// Reads a whole block, or nothing at the end of the stream.
    fn read_block(&mut self, blk: &mut [u8; BLOCK]) -> Result<bool> {
        match read_full(&mut self.r, blk)? {
            0 => Ok(false),
            BLOCK => Ok(true),
            _ => Err(unexpected_eof()),
        }
    }

    fn set_body(&mut self, hdr: &Header) -> Result<()> {
        let size = match hdr.typeflag {
            LINK | SYMLINK | CHAR | BLOCK_DEV | DIR | FIFO => 0,
            _ => u64::try_from(hdr.size).map_err(|_| bad_header())?,
        };
        self.remaining = size;
        self.pad = (size.wrapping_neg() % BLOCK as u64) as usize;
        Ok(())
    }

    /// Reads the body of a PAX header or GNU long name.
    fn read_special(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.take(MAX_SPECIAL_FILE + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_SPECIAL_FILE {
            return Err(invalid("tar header too long"));
        }
        Ok(buf)
    }

    fn read_sparse_map(&mut self, hdr: &mut Header, blk: &[u8; BLOCK]) -> Result<()> {
        let frags = if hdr.typeflag == GNU_SPARSE {
            self.old_gnu_sparse_map(hdr, blk)?
        } else {
            match self.pax_sparse_map(hdr)? {
                Some(frags) => frags,
                None => return Ok(()),
            }
        };
        if hdr.size < 0 {
            return Err(bad_header());
        }
        let mut end = 0;
        let mut checked = Vec::with_capacity(frags.len());
        for (offset, length) in frags {
            if offset < 0
                || length < 0
                || offset > i64::MAX - length
                || offset + length > hdr.size
                || end > offset
            {
                return Err(bad_header());
            }
            end = offset + length;
            checked.push((offset as u64, length as u64));
        }
        self.sparse = Some(Sparse {
            frags: checked,
            idx: 0,
            pos: 0,
            size: hdr.size as u64,
        });
        Ok(())
    }

    /// Reads the sparse map of an old GNU sparse member: in its header, then
    /// in extension blocks ahead of its data.
    fn old_gnu_sparse_map(
        &mut self,
        hdr: &mut Header,
        blk: &[u8; BLOCK],
    ) -> Result<Vec<(i64, i64)>> {
        if format(blk) != Some(Format::Gnu) {
            return Err(bad_header());
        }
        hdr.size = parse_numeric(&blk[483..495])?;
        let mut frags = Vec::new();
        // Entries of 24 bytes, then the byte flagging another extension.
        let mut entries = blk[386..483].to_vec();
        let mut total = entries.len() as u64;
        loop {
            if total >= MAX_SPECIAL_FILE {
                return Err(sparse_too_long());
            }
            let (list, extended) = entries.split_at(entries.len() - 1);
            for entry in list.chunks(24) {
                if entry[0] == 0 {
                    break;
                }
                frags.push((parse_numeric(&entry[..12])?, parse_numeric(&entry[12..])?));
            }
            if extended[0] == 0 {
                return Ok(frags);
            }
            let mut ext = [0u8; BLOCK];
            if !self.read_block(&mut ext)? {
                return Err(unexpected_eof());
            }
            entries = ext[..505].to_vec();
            total += entries.len() as u64;
        }
    }

    /// Reads the sparse map of a PAX sparse member, if `hdr` is one.
    fn pax_sparse_map(&mut self, hdr: &mut Header) -> Result<Option<Vec<(i64, i64)>>> {
        let get = |key: &str| hdr.pax.get(key.as_bytes()).cloned().unwrap_or_default();
        let v1 = match (
            get("GNU.sparse.major").as_slice(),
            get("GNU.sparse.minor").as_slice(),
        ) {
            (b"0", b"0" | b"1") => false,
            (b"1", b"0") => true,
            (b"", b"") if !get("GNU.sparse.map").is_empty() => false,
            _ => return Ok(None),
        };
        let name = get("GNU.sparse.name");
        let mut size = get("GNU.sparse.size");
        if size.is_empty() {
            size = get("GNU.sparse.realsize");
        }
        let numblocks = get("GNU.sparse.numblocks");
        let map = get("GNU.sparse.map");
        if !name.is_empty() {
            hdr.name = name;
        }
        if !size.is_empty() {
            hdr.size = parse_int(&size).ok_or_else(bad_header)?;
        }
        let pairs = |fields: &[&[u8]]| -> Result<Vec<(i64, i64)>> {
            fields
                .chunks(2)
                .map(|pair| {
                    let field = |i: usize| parse_int(pair[i]).ok_or_else(bad_header);
                    Ok((field(0)?, field(1)?))
                })
                .collect()
        };
        let count = |n: &[u8]| -> Result<usize> {
            parse_int(n)
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(bad_header)
        };
        if !v1 {
            let fields: Vec<&[u8]> = if map.is_empty() {
                Vec::new()
            } else {
                map.split(|&c| c == b',').collect()
            };
            if fields.len() != count(&numblocks)? {
                return Err(bad_header());
            }
            return pairs(&fields).map(Some);
        }
        // Version 1.0 keeps the map in the data section: newline-terminated
        // decimals, the entry count first, padded to whole blocks.
        let mut buf = Vec::new();
        self.feed_lines(&mut buf, 1)?;
        let first = buf.iter().position(|&c| c == b'\n').unwrap_or(0);
        let fields = count(&buf[..first])?;
        self.feed_lines(&mut buf, fields + 1)?;
        let fields: Vec<&[u8]> = buf.split(|&c| c == b'\n').skip(1).take(fields).collect();
        pairs(&fields).map(Some)
    }

    /// Reads blocks of the data section into `buf` until it holds `lines`
    /// newlines.
    fn feed_lines(&mut self, buf: &mut Vec<u8>, lines: usize) -> Result<()> {
        let mut have = buf.iter().filter(|&&c| c == b'\n').count();
        while have < lines {
            if (buf.len() + BLOCK) as u64 > MAX_SPECIAL_FILE {
                return Err(sparse_too_long());
            }
            let mut blk = [0u8; BLOCK];
            if read_full(self, &mut blk)? < BLOCK {
                return Err(unexpected_eof());
            }
            have += blk.iter().filter(|&&c| c == b'\n').count();
            buf.extend_from_slice(&blk);
        }
        Ok(())
    }

    /// Reads the data section of the current member.
    fn read_body(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        if len == 0 {
            return Ok(0);
        }
        let n = self.r.read(&mut buf[..len])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= n as u64;
        Ok(n)
    }

    fn read_sparse(&mut self, sp: &mut Sparse, buf: &mut [u8]) -> io::Result<usize> {
        let unreferenced = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse file has unreferenced data",
            )
        };
        if buf.is_empty() {
            return Ok(0);
        }
        if sp.pos == sp.size {
            if self.remaining > 0 {
                return Err(unreferenced());
            }
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(sp.size - sp.pos).unwrap_or(usize::MAX));
        while sp
            .frags
            .get(sp.idx)
            .is_some_and(|&(off, len)| off + len <= sp.pos)
        {
            sp.idx += 1;
        }
        let n = match sp.frags.get(sp.idx) {
            Some(&(off, len)) if sp.pos >= off => {
                let k = want.min(usize::try_from(off + len - sp.pos).unwrap_or(usize::MAX));
                match self.read_body(&mut buf[..k])? {
                    0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "sparse file is missing data",
                        ))
                    }
                    n => n,
                }
            }
            next => {
                let end = next.map_or(sp.size, |&(off, _)| off);
                let k = want.min(usize::try_from(end - sp.pos).unwrap_or(usize::MAX));
                buf[..k].fill(0);
                k
            }
        };
        sp.pos += n as u64;
        if sp.pos == sp.size && self.remaining > 0 {
            return Err(unreferenced());
        }
        Ok(n)
    }
}

impl<R: Read> Read for TarReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(mut sp) = self.sparse.take() else {
            return self.read_body(buf);
        };
        let n = self.read_sparse(&mut sp, buf);
        self.sparse = Some(sp);
        n
    }
}

/// Fills `buf` unless the stream ends first, returning the bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn cut_nul(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}

/// Identifies the header format by its magic, if its checksum is valid,
/// computed with bytes taken as either unsigned or signed.
fn format(blk: &[u8; BLOCK]) -> Option<Format> {
    let sum = parse_octal(&blk[148..156]).ok()?;
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in blk.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    if sum != unsigned && sum != signed {
        return None;
    }
    let (magic, version) = (&blk[257..263], &blk[263..265]);
    Some(if magic == b"ustar\0" && &blk[508..512] == b"tar\0" {
        Format::Star
    } else if magic == b"ustar\0" {
        Format::Ustar
    } else if magic == b"ustar " && version == b" \0" {
        Format::Gnu
    } else {
        Format::V7
    })
}

fn parse_header(blk: &[u8; BLOCK]) -> Result<Header> {
    let format = format(blk).ok_or_else(bad_header)?;
    let mut hdr = Header {
        typeflag: blk[156],
        name: cut_nul(&blk[..100]).to_vec(),
        linkname: cut_nul(&blk[157..257]).to_vec(),
        size: parse_numeric(&blk[124..136])?,
        mode: parse_numeric(&blk[100..108])?,
        uid: parse_numeric(&blk[108..116])?,
        gid: parse_numeric(&blk[116..124])?,
        mtime: (parse_numeric(&blk[136..148])?, 0),
        ..Default::default()
    };
    if format == Format::V7 {
        return Ok(hdr);
    }
    hdr.devmajor = parse_numeric(&blk[329..337])?;
    hdr.devminor = parse_numeric(&blk[337..345])?;
    let prefix = match format {
        Format::Star => {
            parse_numeric(&blk[476..488])?;
            parse_numeric(&blk[488..500])?;
            cut_nul(&blk[345..476])
        }
        Format::Gnu => {
            // Writers before Go 1.8 put a USTAR prefix where GNU keeps
            // atime and ctime; Go takes times that fail to parse for one.
            let times = [&blk[345..357], &blk[357..369]];
            if times.iter().all(|t| t[0] == 0 || parse_numeric(t).is_ok()) {
                &[][..]
            } else {
                Some(cut_nul(&blk[345..500]))
                    .filter(|p| p.is_ascii())
                    .unwrap_or_default()
            }
        }
        _ => cut_nul(&blk[345..500]),
    };
    if !prefix.is_empty() {
        hdr.name = [prefix, b"/", &hdr.name].concat();
    }
    Ok(hdr)
}

/// Parses a numeric header field: base-256 if the high bit is set, octal
/// otherwise.
fn parse_numeric(b: &[u8]) -> Result<i64> {
    if b[0] & 0x80 == 0 {
        return parse_octal(b);
    }
    let inv = if b[0] & 0x40 != 0 { 0xff } else { 0 };
    let mut x: u64 = 0;
    for (i, &c) in b.iter().enumerate() {
        let c = if i == 0 { (c ^ inv) & 0x7f } else { c ^ inv };
        if x >> 56 > 0 {
            return Err(bad_header());
        }
        x = x << 8 | u64::from(c);
    }
    if x >> 63 > 0 {
        return Err(bad_header());
    }
    Ok(if inv == 0xff { !(x as i64) } else { x as i64 })
}

fn parse_octal(b: &[u8]) -> Result<i64> {
    let pad = |c: &u8| *c == b' ' || *c == 0;
    let start = b.iter().position(|c| !pad(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !pad(c)).map_or(start, |i| i + 1);
    let b = &b[start..end];
    if b.is_empty() {
        return Ok(0);
    }
    let b = cut_nul(b);
    if b.is_empty() {
        return Err(bad_header());
    }
    let mut x: u64 = 0;
    for &c in b {
        if !(b'0'..=b'7').contains(&c) {
            return Err(bad_header());
        }
        x = x
            .checked_mul(8)
            .and_then(|x| x.checked_add(u64::from(c - b'0')))
            .ok_or_else(bad_header)?;
    }
    Ok(x as i64)
}

/// Parses a decimal like Go's `strconv.ParseInt(s, 10, 64)`.
fn parse_int(s: &[u8]) -> Option<i64> {
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// Parses a PAX time like Go's archive/tar, to seconds and nanoseconds.
fn parse_pax_time(v: &[u8]) -> Option<(i64, u32)> {
    let (secs, frac) = match v.iter().position(|&c| c == b'.') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, &[][..]),
    };
    let secs = parse_int(secs)?;
    if !frac.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let nsec = frac
        .iter()
        .chain(std::iter::repeat(&b'0'))
        .take(9)
        .fold(0, |n, d| n * 10 + u32::from(d - b'0'));
    if v.first() == Some(&b'-') && nsec > 0 {
        return Some((secs.saturating_sub(1), 1_000_000_000 - nsec));
    }
    Some((secs, nsec))
}

/// Splits a PAX header body into its records. The repeated offset and size
/// records of GNU sparse 0.0 are joined into a 0.1 map.
fn parse_pax(mut buf: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut records = BTreeMap::new();
    let mut sparse: Vec<&[u8]> = Vec::new();
    while !buf.is_empty() {
        let space = buf.iter().position(|&c| c == b' ').ok_or_else(bad_header)?;
        let len = parse_int(&buf[..space])
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n >= 5 && n <= buf.len() && n > space + 1)
            .ok_or_else(bad_header)?;
        let (record, rest) = buf.split_at(len);
        let record = record[space + 1..]
            .strip_suffix(b"\n")
            .ok_or_else(bad_header)?;
        let eq = record
            .iter()
            .position(|&c| c == b'=')
            .ok_or_else(bad_header)?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        let nul = match key {
            b"path" | b"linkpath" | b"uname" | b"gname" => value.contains(&0),
            _ => key.contains(&0),
        };
        if key.is_empty() || nul {
            return Err(bad_header());
        }
        match key {
            b"GNU.sparse.offset" | b"GNU.sparse.numbytes" => {
                let want: &[u8] = if sparse.len() % 2 == 0 {
                    b"GNU.sparse.offset"
                } else {
                    b"GNU.sparse.numbytes"
                };
                if key != want || value.contains(&b',') {
                    return Err(bad_header());
                }
                sparse.push(value);
            }
            _ => {
                records.insert(key.to_vec(), value.to_vec());
            }
        }
        buf = rest;
    }
    if !sparse.is_empty() {
        records.insert(b"GNU.sparse.map".to_vec(), sparse.join(&b','));
    }
    Ok(records)
}

/// Applies the PAX records Go's reader interprets to `hdr`; an empty value
/// keeps the header's.
fn merge_pax(hdr: &mut Header, records: BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    for (key, value) in &records {
        if value.is_empty() {
            continue;
        }
        let int = || parse_int(value).ok_or_else(bad_header);
        let time = || parse_pax_time(value).ok_or_else(bad_header);
        match key.as_slice() {
            b"path" => hdr.name = value.clone(),
            b"linkpath" => hdr.linkname = value.clone(),
            b"uid" => hdr.uid = int()?,
            b"gid" => hdr.gid = int()?,
            b"size" => hdr.size = int()?,
            b"mtime" => hdr.mtime = time()?,
            b"atime" | b"ctime" => {
                time()?;
            }
            _ => {}
        }
    }
    hdr.pax = records;
    Ok(())
}

/// Go's `path.Clean` over bytes.
fn clean(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let rooted = p[0] == b'/';
    let n = p.len();
    let mut out = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        (r, dotdot) = (1, 1);
    }
    while r < n {
        if p[r] == b'/' || (p[r] == b'.' && (r + 1 == n || p[r + 1] == b'/')) {
            r += 1;
        } else if p[r] == b'.' && p[r + 1] == b'.' && (r + 2 == n || p[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && p[r] != b'/' {
                out.push(p[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        out.push(b'.');
    }
    out
}

/// Go's `path.Join` over bytes.
fn join(parts: &[&[u8]]) -> Vec<u8> {
    let parts: Vec<&[u8]> = parts.iter().copied().filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Vec::new();
    }
    clean(&parts.join(&b'/'))
}

/// Go's `path.Split`: everything up to the last slash, and the rest.
fn split(p: &[u8]) -> (&[u8], &[u8]) {
    match p.iter().rposition(|&c| c == b'/') {
        Some(i) => p.split_at(i + 1),
        None => (&[], p),
    }
}

fn components(p: &[u8]) -> Vec<Vec<u8>> {
    p.split(|&c| c == b'/').map(<[u8]>::to_vec).collect()
}

type NodeRef = Rc<RefCell<Node>>;

/// What later members observe of an applied inode. Hard links share one.
#[derive(Default)]
struct Node {
    typeflag: u8,
    linkname: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (u64, u32),
    xattrs: Xattrs,
    children: HashMap<Vec<u8>, NodeRef>,
}

/// A directory as Apply and `nydus build` create one implicitly: 0755
/// root:root. Apply dates it to the time it ran, which no layer can
/// reproduce, so it gets the epoch, as `nydus build` gives it.
fn new_dir() -> NodeRef {
    new_node(DIR, 0o755)
}

fn new_node(typeflag: u8, mode: u32) -> NodeRef {
    Rc::new(RefCell::new(Node {
        typeflag,
        mode,
        ..Default::default()
    }))
}

struct Tree {
    root: NodeRef,
    /// The paths global headers removed that no later member has replaced
    /// yet, and whether each held a directory.
    removed: BTreeMap<Vec<u8>, bool>,
}

impl Tree {
    fn new() -> Self {
        Tree {
            root: new_dir(),
            removed: BTreeMap::new(),
        }
    }

    /// Records `hdr` the way Apply lands it and returns the members to
    /// emit for it, none for one Apply ignores: the member itself, after
    /// any implicit directory `nydus build` would not create as Apply does.
    fn apply(&mut self, hdr: &Header) -> Result<Vec<Member>> {
        let typeflag = match hdr.typeflag {
            REG | DIR | SYMLINK | LINK | CHAR | BLOCK_DEV | FIFO | XGLOBAL => hdr.typeflag,
            CONT | GNU_SPARSE => REG,
            GNU_DUMPDIR => DIR,
            other => {
                return Err(Error::Unsupported(format!(
                    "unsupported tar entry type {:?}",
                    other as char
                )))
            }
        };
        let name = clean(&hdr.name);
        let (parent_path, base) = split(&name);
        let parent_path = self.root_path(parent_path)?;
        let target = join(&[&parent_path, &join(&[b"/", base])]);
        if target == b"/" {
            return Ok(Vec::new());
        }
        if target.len() >= PATH_MAX {
            return Err(invalid("member path: file name too long"));
        }
        let rel = &target[1..];
        if rel.split(|&c| c == b'/').any(|c| c.len() > NAME_MAX) {
            return Err(invalid("name component too long"));
        }
        let global = typeflag == XGLOBAL;
        let (parent, mut out) = self.mkparent(&parent_path, global)?;
        validate_whiteout(&target)?;

        let name = split(&target).1.to_vec();
        let existing = parent.borrow().children.get(&name).cloned();
        if global {
            // Apply removes whatever the name held before ignoring the
            // header. Members cannot express that, so a later one must
            // replace it.
            if let Some(existing) = existing {
                parent.borrow_mut().children.remove(&name);
                self.forget_removed_under(rel);
                self.removed
                    .insert(rel.to_vec(), existing.borrow().typeflag == DIR);
            }
            return Ok(out);
        }
        self.replace_removed(rel, typeflag == DIR)?;
        let existing = match existing {
            Some(e) if typeflag == DIR && e.borrow().typeflag == DIR => Some(e),
            Some(_) => {
                parent.borrow_mut().children.remove(&name);
                None
            }
            None => None,
        };

        let mut mode = (hdr.mode & 0o7777) as u32;
        let (node, kind) = match typeflag {
            DIR => (existing.clone().unwrap_or_else(new_dir), Kind::Dir),
            REG => (new_node(REG, 0), Kind::Reg(hdr.size as u64)),
            CHAR | BLOCK_DEV => {
                // mknod(2) keeps 12 bits of major and 20 of minor.
                let rdev = libc::makedev(hdr.devmajor as u32 & 0xfff, hdr.devminor as u32 & 0xfffff)
                    as u32;
                let kind = if typeflag == CHAR {
                    Kind::Char(rdev)
                } else {
                    Kind::Block(rdev)
                };
                (new_node(typeflag, 0), kind)
            }
            FIFO => (new_node(FIFO, 0), Kind::Fifo),
            SYMLINK => {
                if hdr.linkname.is_empty() {
                    return Err(invalid("empty symlink target"));
                }
                if hdr.linkname.len() >= PATH_MAX {
                    return Err(invalid("symlink target: file name too long"));
                }
                mode = 0o777;
                let node = new_node(SYMLINK, 0);
                node.borrow_mut().linkname = hdr.linkname.clone();
                (node, Kind::Symlink(hdr.linkname.clone()))
            }
            _ => {
                // Like containerd's hardlinkRootPath: the link's parent is
                // resolved, its last component is not.
                let (link_parent, link_base) = split(&hdr.linkname);
                let link_target = join(&[&self.root_path(link_parent)?, link_base]);
                let what = || format!("hardlink target {}", show(&hdr.linkname));
                let node = self
                    .lookup(&link_target)
                    .with_context(what)?
                    .ok_or_else(|| invalid(format!("{} not found", what())))?;
                if node.borrow().typeflag == DIR {
                    return Err(invalid(format!("{} is a directory", what())));
                }
                (node, Kind::Link(components(&link_target[1..])))
            }
        };
        let is_new = !existing.is_some_and(|e| Rc::ptr_eq(&e, &node));
        let (parent_mode, parent_gid) = {
            let parent = parent.borrow();
            (parent.mode, parent.gid)
        };
        let mut n = node.borrow_mut();
        if is_new && typeflag != LINK && parent_mode & 0o2000 != 0 {
            // A new inode in a setgid directory takes the directory's group.
            n.gid = parent_gid;
        }
        let uid = apply_id(hdr.uid, n.uid);
        let gid = apply_id(hdr.gid, n.gid);
        let mut xattrs = apply_xattrs(n.typeflag, &hdr.pax)?;
        if typeflag == DIR {
            // Apply sets xattrs on the directory it merges into.
            n.xattrs.append(&mut xattrs);
            xattrs = n.xattrs.clone();
        }
        // Apply sets the member's metadata on the inode, a hard link's too,
        // except that chmod does not apply to a symlink.
        if n.typeflag != SYMLINK || typeflag == SYMLINK {
            n.mode = mode;
        }
        let mtime = bound_time(hdr.mtime);
        (n.uid, n.gid, n.mtime) = (uid, gid, mtime);
        drop(n);
        parent.borrow_mut().children.insert(name, node);
        out.push(Member {
            path: components(rel),
            kind,
            mode: mode as u16,
            uid,
            gid,
            mtime: mtime.0,
            mtime_nsec: mtime.1,
            xattrs,
        });
        Ok(out)
    }

    /// Returns the directory at the resolved path `p`, recording missing
    /// ones as the implicit directories Apply creates. mkdir(2) in a setgid
    /// directory inherits its group, which `nydus build` cannot know, so
    /// those are returned as members to emit; Apply's chmod clears the
    /// setgid bit they would inherit too. With `emit_all`, every directory
    /// it creates is returned, for a member that is not emitted to imply
    /// them.
    fn mkparent(&mut self, p: &[u8], emit_all: bool) -> Result<(NodeRef, Vec<Member>)> {
        let mut out = Vec::new();
        let mut cur = self.root.clone();
        let mut dir = Vec::new();
        for comp in p.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
            dir = join(&[&dir, comp]);
            let child = cur.borrow().children.get(comp).cloned();
            let node = match child {
                Some(node) if node.borrow().typeflag == DIR => node,
                Some(_) => return Err(invalid(format!("parent {} is not a directory", show(p)))),
                None => {
                    self.replace_removed(&dir, true)?;
                    let node = new_dir();
                    let (setgid, gid) = {
                        let cur = cur.borrow();
                        (cur.mode & 0o2000 != 0, cur.gid)
                    };
                    if setgid {
                        node.borrow_mut().gid = gid;
                    }
                    if emit_all || setgid {
                        out.push(Member {
                            path: components(&dir),
                            kind: Kind::Dir,
                            mode: 0o755,
                            uid: 0,
                            gid: node.borrow().gid,
                            mtime: 0,
                            mtime_nsec: 0,
                            xattrs: Xattrs::new(),
                        });
                    }
                    cur.borrow_mut()
                        .children
                        .insert(comp.to_vec(), node.clone());
                    node
                }
            };
            cur = node;
        }
        Ok((cur, out))
    }

    /// Records that a member, or an implicit directory when `dir` is set,
    /// lands on `p`. If a global header removed `p`, `nydus build` replaces
    /// what `p` held as Apply does, unless both are directories: it would
    /// merge them, keeping the entries Apply removed.
    fn replace_removed(&mut self, p: &[u8], dir: bool) -> Result<()> {
        if !dir {
            // A non-directory replaces p's subtree, with whatever was
            // removed in it.
            self.forget_removed_under(p);
        }
        match self.removed.get(p) {
            None => Ok(()),
            Some(true) if dir => Err(invalid(format!(
                "directory {} removed by a global header is created again",
                show(p)
            ))),
            Some(_) => {
                self.removed.remove(p);
                Ok(())
            }
        }
    }

    /// Drops the pending removals below `p`.
    fn forget_removed_under(&mut self, p: &[u8]) {
        let prefix = [p, b"/"].concat();
        self.removed
            .retain(|removed, _| !removed.starts_with(&prefix));
    }

    /// Finds `p` like lstat(2): symlinks in leading components are followed
    /// within the root, the last component is not. `None` means `p` does
    /// not exist. Like lstat(2), it fails for a path of PATH_MAX bytes or
    /// more and after following too many symlinks; both bound the work a
    /// hostile layer can demand.
    fn lookup(&self, p: &[u8]) -> Result<Option<NodeRef>> {
        self.lookup_depth(p, 0)
    }

    fn lookup_depth(&self, p: &[u8], followed: usize) -> Result<Option<NodeRef>> {
        if followed > MAX_LINKS_FOLLOWED {
            return Err(invalid("too many levels of symbolic links"));
        }
        if p.len() >= PATH_MAX {
            return Err(invalid("file name too long"));
        }
        let p = clean(&[b"/", p].concat());
        let comps: Vec<&[u8]> = p[1..].split(|&c| c == b'/').collect();
        let mut cur = self.root.clone();
        for (i, comp) in comps.iter().enumerate() {
            if comp.is_empty() {
                break;
            }
            let Some(node) = cur.borrow().children.get(*comp).cloned() else {
                return Ok(None);
            };
            if i == comps.len() - 1 {
                return Ok(Some(node));
            }
            let (typeflag, link) = {
                let n = node.borrow();
                (n.typeflag, n.linkname.clone())
            };
            match typeflag {
                DIR => cur = node,
                SYMLINK => {
                    let link = if link.starts_with(b"/") {
                        link
                    } else {
                        join(&[b"/", &join(&comps[..i]), &link])
                    };
                    let mut rest = vec![link.as_slice()];
                    rest.extend_from_slice(&comps[i + 1..]);
                    return self.lookup_depth(&join(&rest), followed + 1);
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    /// Resolves `p` within the root through the symlinks recorded so far,
    /// following continuity's `fs.RootPath` step for step.
    fn root_path(&self, p: &[u8]) -> Result<Vec<u8>> {
        if p.is_empty() {
            return Ok(b"/".to_vec());
        }
        let mut p = p.to_vec();
        let mut walked = 0;
        loop {
            let before = walked;
            p = self.walk_links(&p, &mut walked)?;
            if before == walked {
                let next = join(&[b"/", &p]);
                if p == next {
                    return Ok(p);
                }
                p = next;
            }
        }
    }

    fn walk_link(&self, p: &[u8], walked: &mut usize) -> Result<(Vec<u8>, bool)> {
        if *walked > MAX_LINKS_WALKED {
            return Err(invalid("too many symlinks"));
        }
        let p = join(&[b"/", p]);
        if p == b"/" {
            return Ok((p, false));
        }
        match self.lookup(&p)? {
            Some(node) if node.borrow().typeflag == SYMLINK => {
                *walked += 1;
                let link = node.borrow().linkname.clone();
                Ok((link, true))
            }
            _ => Ok((p, false)),
        }
    }

    /// continuity's `walkLinks`, which recurses on the parent, as a loop
    /// over the components from the left making the same `walkLink` calls:
    /// a member name may hold a megabyte of components.
    fn walk_links(&self, p: &[u8], walked: &mut usize) -> Result<Vec<u8>> {
        let mut comps = p.split(|&c| c == b'/').filter(|c| !c.is_empty());
        let mut dir = if p.starts_with(b"/") {
            b"/".to_vec()
        } else {
            // A relative first component resolves to its link target as is.
            self.walk_link(comps.next().unwrap_or_default(), walked)?.0
        };
        for file in comps {
            let (next, is_link) = self.walk_link(&join(&[&dir, file]), walked)?;
            dir = if !is_link || next.starts_with(b"/") {
                next
            } else {
                join(&[&dir, &next])
            };
        }
        Ok(dir)
    }

    /// Mirrors the last pass of Apply, which sets each directory member's
    /// mtime again, resolving its name, as archived, through the symlinks
    /// of the finished tree: a name that no longer resolves fails the
    /// layer, and one that now resolves elsewhere restamps whatever is
    /// there. Returns a member for each inode whose mtime changes.
    fn restamp_dirs(&self, dirs: Vec<(Vec<u8>, (u64, u32))>) -> Result<Vec<Member>> {
        let mut stamps: Vec<(NodeRef, Vec<u8>, (u64, u32))> = Vec::new();
        let mut index = HashMap::new();
        for (name, mtime) in dirs {
            let what = || format!("layer tar directory {}", show(&name));
            let p = self.root_path(&name).with_context(what)?;
            if p == b"/" {
                continue;
            }
            let node = self
                .lookup(&p)
                .with_context(what)?
                .ok_or_else(|| invalid(format!("{} no longer resolves", what())))?;
            let stamp = (node.clone(), p[1..].to_vec(), mtime);
            match index.entry(Rc::as_ptr(&node)) {
                Entry::Occupied(i) => stamps[*i.get()] = stamp,
                Entry::Vacant(i) => {
                    i.insert(stamps.len());
                    stamps.push(stamp);
                }
            }
        }
        let mut out = Vec::new();
        for (node, name, mtime) in stamps {
            let mut node = node.borrow_mut();
            if node.mtime == mtime {
                continue;
            }
            node.mtime = mtime;
            out.push(Member {
                path: components(&name),
                kind: Kind::Restamp,
                mode: node.mode as u16,
                uid: node.uid,
                gid: node.gid,
                mtime: mtime.0,
                mtime_nsec: mtime.1,
                xattrs: Xattrs::new(),
            });
        }
        Ok(out)
    }
}

/// Rejects whiteout names that would remove something outside their own
/// directory, as Apply does. `p` is absolute and clean.
fn validate_whiteout(p: &[u8]) -> Result<()> {
    let (dir, base) = split(p);
    let Some(original) = base.strip_prefix(b".wh.") else {
        return Ok(());
    };
    if base == b".wh..wh..opq" {
        return Ok(());
    }
    let dir = clean(dir);
    let original = join(&[&dir, original]);
    let prefix = [dir.strip_suffix(b"/").unwrap_or(&dir), b"/"].concat();
    if original == dir || !original.starts_with(&prefix) {
        return Err(invalid(format!("invalid whiteout name {}", show(base))));
    }
    Ok(())
}

/// Keeps the xattrs Apply sets on an inode of type `typeflag`, checking
/// each name in the order lsetxattr(2) does and dropping what Apply
/// ignores: trusted.*, which containerd refuses to set, user.* on an inode
/// other than a regular file or directory, names no handler serves, and
/// POSIX ACLs on a symlink. Only an ACL's framing is checked; the kernel's
/// validation of its entries, and its folding of a minimal ACL into the
/// mode, are not reproduced.
fn apply_xattrs(typeflag: u8, records: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Xattrs> {
    let mut xattrs = Xattrs::new();
    for (key, value) in records {
        let Some(name) = key.strip_prefix(b"SCHILY.xattr.") else {
            continue;
        };
        if name.starts_with(b"trusted.") {
            continue;
        }
        let bad = || invalid(format!("invalid xattr {}", show(name)));
        if name.is_empty() || name.len() > XATTR_NAME_MAX || value.len() > XATTR_SIZE_MAX {
            return Err(bad());
        }
        if name.starts_with(b"user.") {
            if typeflag != REG && typeflag != DIR {
                continue;
            }
            if name == b"user." {
                return Err(bad());
            }
        } else if name.starts_with(b"security.") {
            if name == b"security." {
                return Err(bad());
            }
        } else if name == b"system.posix_acl_access" || name == b"system.posix_acl_default" {
            // An empty value removes the ACL, which a new inode lacks.
            if typeflag == SYMLINK || value.is_empty() {
                continue;
            }
            if name == b"system.posix_acl_default" && typeflag != DIR {
                return Err(invalid("default ACL on a non-directory"));
            }
            // A little-endian version 2 header and whole 8-byte entries.
            if value.len() < 12 || (value.len() - 4) % 8 != 0 || value[..4] != [2, 0, 0, 0] {
                return Err(bad());
            }
        } else {
            continue;
        }
        xattrs.insert(name.to_vec(), value.clone());
    }
    Ok(xattrs)
}

/// Bounds a time to what Apply's `os.Chtimes` can set, the epoch otherwise.
fn bound_time((secs, nsec): (i64, u32)) -> (u64, u32) {
    if secs < 0 || (secs, nsec) > MAX_TIME {
        return (0, 0);
    }
    (secs as u64, nsec)
}

/// Returns the owner lchown(2) leaves on an inode owned by `current`: the
/// kernel takes the low 32 bits and treats all-ones as "unchanged".
fn apply_id(id: i64, current: u32) -> u32 {
    match id as u32 {
        u32::MAX => current,
        id => id,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const MTIME: u64 = 1_700_000_000;

    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        field.copy_from_slice(format!("{value:0width$o}\0").as_bytes());
    }

    fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
        let body = [b" ", key, b"=", value, b"\n"].concat();
        let mut len = body.len();
        while len.to_string().len() + body.len() != len {
            len = len.to_string().len() + body.len();
        }
        [len.to_string().as_bytes(), &body].concat()
    }

    /// A tar archive built like Go's tar.Writer builds one: what does not
    /// fit the USTAR header goes into PAX records.
    #[derive(Default)]
    struct Tar(Vec<u8>);

    impl Tar {
        fn raw(mut self, typeflag: u8, name: &[u8], link: &[u8], mode: u64, data: &[u8]) -> Self {
            let mut b = [0u8; BLOCK];
            b[..name.len()].copy_from_slice(name);
            octal(&mut b[100..108], mode);
            octal(&mut b[108..116], 0);
            octal(&mut b[116..124], 0);
            octal(&mut b[124..136], data.len() as u64);
            octal(&mut b[136..148], MTIME);
            b[156] = typeflag;
            b[157..157 + link.len()].copy_from_slice(link);
            b[257..263].copy_from_slice(b"ustar\0");
            b[263..265].copy_from_slice(b"00");
            b[148..156].fill(b' ');
            let sum = b.iter().map(|&c| u64::from(c)).sum();
            octal(&mut b[148..155], sum);
            self.0.extend_from_slice(&b);
            self.0.extend_from_slice(data);
            self.0.resize(self.0.len().next_multiple_of(BLOCK), 0);
            self
        }

        fn add(
            self,
            typeflag: u8,
            name: &str,
            link: &str,
            mode: u64,
            records: &[(&str, &[u8])],
        ) -> Self {
            let mut pax: Vec<u8> = records
                .iter()
                .flat_map(|(k, v)| pax_record(k.as_bytes(), v))
                .collect();
            let (mut name, mut link) = (name.as_bytes(), link.as_bytes());
            if name.len() > 100 {
                pax.extend(pax_record(b"path", name));
                name = b"";
            }
            if link.len() > 100 {
                pax.extend(pax_record(b"linkpath", link));
                link = b"";
            }
            let tar = if pax.is_empty() {
                self
            } else {
                self.raw(XHEADER, b"PaxHeader", b"", 0o644, &pax)
            };
            let data: &[u8] = if typeflag == REG { b"x" } else { b"" };
            tar.raw(typeflag, name, link, mode, data)
        }

        fn reg(self, name: &str) -> Self {
            self.add(REG, name, "", 0o644, &[])
        }

        fn dir(self, name: &str) -> Self {
            self.add(DIR, name, "", 0o755, &[])
        }

        fn sym(self, name: &str, target: &str) -> Self {
            self.add(SYMLINK, name, target, 0o777, &[])
        }

        fn link(self, name: &str, target: &str) -> Self {
            self.add(LINK, name, target, 0o644, &[])
        }

        fn global(self, name: &str) -> Self {
            self.add(XGLOBAL, name, "", 0, &[])
        }

        fn finish(mut self) -> Vec<u8> {
            self.0.extend_from_slice(&[0; 2 * BLOCK]);
            self.0
        }
    }

    fn run(tar: &[u8]) -> Result<Vec<(Member, Vec<u8>)>> {
        run_reader(tar)
    }

    fn run_reader(tar: impl Read) -> Result<Vec<(Member, Vec<u8>)>> {
        let mut out = Vec::new();
        normalize(tar, |member, data| {
            let mut buf = Vec::new();
            data.read_to_end(&mut buf)?;
            out.push((member, buf));
            Ok(())
        })?;
        Ok(out)
    }

    fn text(p: &[u8]) -> String {
        String::from_utf8_lossy(p).into_owned()
    }

    /// "path type link", or "path R mtime" for a restamp.
    fn describe(m: &Member) -> String {
        let path = |p: &[Vec<u8>]| text(&p.join(&b'/'));
        let (kind, extra) = match &m.kind {
            Kind::Dir => ('5', String::new()),
            Kind::Reg(_) => ('0', String::new()),
            Kind::Symlink(target) => ('2', text(target)),
            Kind::Link(target) => ('1', path(target)),
            Kind::Char(_) => ('3', String::new()),
            Kind::Block(_) => ('4', String::new()),
            Kind::Fifo => ('6', String::new()),
            Kind::Restamp => ('R', m.mtime.to_string()),
        };
        format!("{} {kind} {extra}", path(&m.path))
            .trim_end()
            .to_string()
    }

    /// The members described and joined by "|", or "err: " and the error.
    fn outline(tar: &[u8]) -> String {
        match run(tar) {
            Ok(members) => members
                .iter()
                .map(|(m, _)| describe(m))
                .collect::<Vec<_>>()
                .join("|"),
            Err(err) => format!("err: {}", err.report()),
        }
    }

    fn check(cases: Vec<(&str, Vec<u8>, &str)>) {
        for (name, tar, want) in cases {
            let got = outline(&tar);
            match want.strip_prefix("err: ") {
                Some(err) => assert!(
                    got.starts_with("err: ") && got.contains(err),
                    "{name}: {got}"
                ),
                None => assert_eq!(got, want, "{name}"),
            }
        }
    }

    fn t() -> Tar {
        Tar::default()
    }

    #[test]
    fn member_paths_resolve_like_apply() {
        check(vec![
            (
                "parent symlink",
                t().dir("b/").sym("a", "b").reg("a/f").finish(),
                "b 5|a 2 b|b/f 0",
            ),
            (
                "absolute parent symlink",
                t().dir("etc/").sym("l", "/etc").reg("l/x").finish(),
                "etc 5|l 2 /etc|etc/x 0",
            ),
            (
                "escaping parent symlink",
                t().sym("a", "../../..").reg("a/f").finish(),
                "a 2 ../../..|f 0",
            ),
            (
                "escaping name",
                t().reg("../../x").reg("/y").finish(),
                "x 0|y 0",
            ),
            ("root member", t().dir("./").reg("f").finish(), "f 0"),
            (
                "hard link through symlink",
                t().dir("etc/")
                    .reg("etc/passwd")
                    .sym("l", "/etc")
                    .link("p", "l/passwd")
                    .finish(),
                "etc 5|etc/passwd 0|l 2 /etc|p 1 etc/passwd",
            ),
            (
                "hard link to symlink",
                t().sym("s", "gone").link("h", "s").finish(),
                "s 2 gone|h 1 s",
            ),
            (
                "hard link to missing target",
                t().link("p", "nope").finish(),
                "err: not found",
            ),
            (
                "hard link to directory",
                t().dir("d/").link("p", "d").finish(),
                "err: is a directory",
            ),
            (
                "parent regular file",
                t().reg("x").reg("x/y").finish(),
                "err: not a directory",
            ),
            (
                "invalid whiteout",
                t().reg("d/.wh..").finish(),
                "err: invalid whiteout",
            ),
            (
                "invalid root whiteout",
                t().reg(".wh...").finish(),
                "err: invalid whiteout",
            ),
            (
                "whiteouts kept",
                t().reg(".wh.gone").reg("d/.wh..wh..opq").finish(),
                ".wh.gone 0|d/.wh..wh..opq 0",
            ),
            (
                "empty symlink",
                t().sym("s", "").finish(),
                "err: empty symlink",
            ),
            (
                "unsupported type",
                t().add(b'V', "v", "", 0, &[]).finish(),
                "err: unsupported tar entry type",
            ),
            (
                "symlink loop",
                t().sym("l", "l/x").reg("l/f").finish(),
                "err: too many levels of symbolic links",
            ),
            (
                "path too long",
                t().reg(&("a/".repeat(2048) + "f")).finish(),
                "err: file name too long",
            ),
            (
                "long name resolving short",
                t().reg(&("../".repeat(2048) + "f")).finish(),
                "f 0",
            ),
            (
                "name too long",
                t().reg(&"n".repeat(256)).finish(),
                "err: name component too long",
            ),
            (
                "symlink target too long",
                t().sym("s", &"t".repeat(4096)).finish(),
                "err: file name too long",
            ),
            (
                "global header",
                t().global("GlobalHead.0.0").reg("f").finish(),
                "f 0",
            ),
            (
                "global header implies parents",
                t().global("tmp/GlobalHead.1.1").finish(),
                "tmp 5",
            ),
            (
                "global header removes member",
                t().reg("f").global("f").finish(),
                "err: no later member replaces",
            ),
            (
                "global header removal replaced",
                t().reg("f").global("f").reg("f").finish(),
                "f 0|f 0",
            ),
            (
                "global header removal replaced by directory",
                t().reg("f").global("f").reg("f/x").finish(),
                "f 0|f/x 0",
            ),
            (
                "global header removes directory",
                t().reg("d/x").global("d").dir("d/").finish(),
                "err: is created again",
            ),
            (
                "global header removal under replaced directory",
                t().reg("d/x").global("d/x").reg("d").finish(),
                "d/x 0|d 0",
            ),
        ]);
    }

    #[test]
    fn directory_mtimes_are_restamped_where_names_resolve_at_the_end() {
        let dir =
            |t: Tar, name: &str, mtime: &[u8]| t.add(DIR, name, "", 0o755, &[("mtime", mtime)]);
        check(vec![
            (
                "replaced by file",
                dir(t(), "d/", b"5").reg("d").finish(),
                "d 5|d 0|d R 5",
            ),
            (
                "replaced by symlink to dir",
                dir(dir(t(), "e/", b"6"), "d/", b"5").sym("d", "e").finish(),
                "e 5|d 5|d 2 e|e R 5",
            ),
            (
                "replaced by dangling symlink",
                dir(t(), "d/", b"5").sym("d", "gone").finish(),
                "err: no longer resolves",
            ),
            (
                "parent replaced by file",
                t().dir("p/").dir("p/d/").reg("p").finish(),
                "err: no longer resolves",
            ),
            (
                "unchanged",
                dir(dir(t(), "d/", b"5").reg("d/f"), "d/", b"5").finish(),
                "d 5|d/f 0|d 5",
            ),
        ]);
    }

    #[test]
    fn owners_follow_lchown_and_setgid_directories() {
        let ids = |t: Tar, typeflag, name: &str, link: &str, uid: &[u8], gid: &[u8]| {
            t.add(typeflag, name, link, 0o755, &[("uid", uid), ("gid", gid)])
        };
        let mut tar = ids(t(), DIR, "d/", "", b"5", b"6");
        tar = ids(tar, DIR, "d/", "", b"-1", b"8");
        tar = ids(tar, REG, "d/f", "", b"9", b"10");
        tar = ids(tar, LINK, "d/h", "d/f", b"11", b"-1");
        tar = ids(
            tar.add(DIR, "s/", "", 0o2755, &[("gid", b"7")]),
            REG,
            "s/f",
            "",
            b"-1",
            b"-1",
        );
        tar = ids(tar, REG, "g", "", b"-1", b"-1").reg("s/a/b/f");
        let got: Vec<String> = run(&tar.finish())
            .unwrap()
            .iter()
            .map(|(m, _)| {
                format!(
                    "{} {:o} {}:{}",
                    text(&m.path.join(&b'/')),
                    m.mode,
                    m.uid,
                    m.gid
                )
            })
            .collect();
        // lchown(2) keeps an owner given as -1, and only the directory
        // mkdir(2) creates in a setgid one inherits its group.
        assert_eq!(
            got,
            [
                "d 755 5:6",
                "d 755 5:8",
                "d/f 755 9:10",
                "d/h 755 11:10",
                "s 2755 0:7",
                "s/f 755 0:7",
                "g 755 0:0",
                "s/a 755 0:7",
                "s/a/b/f 644 0:0",
            ]
        );
    }

    #[test]
    fn metadata_is_bounded_and_directory_xattrs_merge() {
        let tar = t()
            .add(
                REG,
                "f",
                "",
                0o104755,
                &[
                    ("mtime", b"-1"),
                    ("SCHILY.xattr.user.a", b"1"),
                    ("SCHILY.xattr.trusted.overlay.x", b"y"),
                    ("SCHILY.xattr.nonamespace", b"z"),
                ],
            )
            .add(
                SYMLINK,
                "s",
                "f",
                0o777,
                &[
                    ("SCHILY.xattr.user.b", b"1"),
                    ("SCHILY.xattr.security.c", b"2"),
                ],
            )
            .add(
                DIR,
                "d/",
                "",
                0o755,
                &[
                    ("SCHILY.xattr.user.old", b"1"),
                    ("SCHILY.xattr.user.both", b"old"),
                ],
            )
            .add(DIR, "d/", "", 0o755, &[("SCHILY.xattr.user.both", b"new")])
            .add(REG, "n", "", 0o644, &[("mtime", b"1.000000005")])
            .finish();
        let members = run(&tar).unwrap();
        let xattrs = |i: usize| -> Vec<String> {
            let m: &Member = &members[i].0;
            m.xattrs
                .iter()
                .map(|(k, v)| format!("{}={}", text(k), text(v)))
                .collect()
        };
        let (f, n) = (&members[0].0, &members[4].0);
        assert_eq!((f.mode, f.mtime, f.mtime_nsec), (0o4755, 0, 0));
        assert_eq!(xattrs(0), ["user.a=1"]);
        assert_eq!(xattrs(1), ["security.c=2"]);
        assert_eq!(xattrs(3), ["user.both=new", "user.old=1"]);
        assert_eq!((n.mtime, n.mtime_nsec), (1, 5));
        assert_eq!(members[0].1, b"x");
    }

    #[test]
    fn xattr_names_are_checked_like_lsetxattr() {
        let acl: &[u8] = b"\x02\x00\x00\x00\x01\x00\x06\x00\xff\xff\xff\xff";
        let long = format!("x.{}", "n".repeat(254));
        let big = vec![b'v'; 65537];
        for (typeflag, xattrs, want) in [
            (
                REG,
                vec![("user", b"v".as_slice()), ("security", b"v"), ("x.y", b"v")],
                "",
            ),
            (REG, vec![("user.", b"v".as_slice())], "err: invalid xattr"),
            (
                SYMLINK,
                vec![("security.", b"v".as_slice())],
                "err: invalid xattr",
            ),
            (REG, vec![("", b"v".as_slice())], "err: invalid xattr"),
            (
                REG,
                vec![(long.as_str(), b"v".as_slice())],
                "err: invalid xattr",
            ),
            (
                SYMLINK,
                vec![("user.a", big.as_slice())],
                "err: invalid xattr",
            ),
            (REG, vec![("trusted.overlay.opaque", b"y".as_slice())], ""),
            (SYMLINK, vec![("user.a", b"v".as_slice())], ""),
            (
                DIR,
                vec![
                    ("system.posix_acl_access", acl),
                    ("system.posix_acl_default", acl),
                ],
                "system.posix_acl_access system.posix_acl_default",
            ),
            (SYMLINK, vec![("system.posix_acl_access", acl)], ""),
            (REG, vec![("system.posix_acl_default", b"".as_slice())], ""),
            (
                REG,
                vec![("system.posix_acl_default", acl)],
                "err: non-directory",
            ),
            (
                REG,
                vec![(
                    "system.posix_acl_access",
                    b"\x02\x00\x00\x00\x01".as_slice(),
                )],
                "err: invalid xattr",
            ),
        ] {
            let keys: Vec<String> = xattrs
                .iter()
                .map(|(k, _)| format!("SCHILY.xattr.{k}"))
                .collect();
            let records: Vec<(&str, &[u8])> = keys
                .iter()
                .zip(&xattrs)
                .map(|(k, (_, v))| (k.as_str(), *v))
                .collect();
            let link = if typeflag == SYMLINK { "t" } else { "" };
            let tar = t().add(typeflag, "n", link, 0o755, &records).finish();
            let got = match run(&tar) {
                Ok(members) => {
                    let names: Vec<String> = members[0].0.xattrs.keys().map(|k| text(k)).collect();
                    names.join(" ")
                }
                Err(err) => format!("err: {}", err.report()),
            };
            match want.strip_prefix("err: ") {
                Some(err) => assert!(got.contains(err), "{xattrs:?}: {got}"),
                None => assert_eq!(got, want, "{xattrs:?}"),
            }
        }
    }

    #[test]
    fn pax_records_may_hold_newlines() {
        let name = "n".repeat(120) + "\nx";
        let tar = t()
            .add(REG, "f", "", 0o644, &[("SCHILY.xattr.user.a\nb", b"v\n1")])
            .reg(&name)
            .finish();
        let members = run(&tar).unwrap();
        let xattr = members[0].0.xattrs.iter().next().unwrap();
        assert_eq!(xattr, (&b"user.a\nb".to_vec(), &b"v\n1".to_vec()));
        assert_eq!(members[1].0.path, [name.into_bytes()]);
    }

    #[test]
    fn sparse_members_read_back_with_zeroed_holes() {
        // GNU tar 1.30 archives of a 1 MiB file holding "head" at offset 0
        // and 'x' in its last byte: --format=gnu (old GNU sparse) and
        // --format=pax (PAX sparse 1.0), gzipped.
        for fixture in [
            "H4sIAAAAAAACA+3QWwrCMBCF4VlKViCZXBfiCgJe+lTBKNjd22IpCtU+iIL4fw+ZITkwYXbyebaXQhiq5qj3teeGQzS65FWzt0msczY6Mesv/E3O9VSOxkhX2npo96uu1tnc0vtb2xmNvU69z3n2Pjzkb/3LAeFZqNmWjQAAAAAAAAAAAAAAgF92YQUA8J+uorSUngAoAAA=",
            "H4sIAAAAAAACA+3VwUrDMBzH8ZzzFH2CLmnSpD30qp5EEB8gaKeVrZNmwubTm/biNhUvczD9fiiE/v8JlIRfms9uwuaqDQ/tEHNTOeO9ms3FUanEWTuNyeGoCl8IXRbOaO2NckJpbXQhso04gde4DkP6FPE/FUV2eX2Xx5cwxDZfhufV0Gh5UO36VFWy0LvVPizbZi7NXnFowyJ2b22jla1K76RR2XLdpZna1+mxVeXyuvTGOVfVYzd87lZj10/d++/XChxBPkundzsd3kW3aH/lCtjJv/al3h3H9OvxLtjPvy+VFpk6Zf63oY+r/jHfxvjlvJ/6h5fbmTBSSatqJ1Ngra0+Xqb0KlL2xz2lXz+7AAAAAAAAAAAAAADAWduwBQAAAAAAAAAAAAAAAAAAnJ93ADcwQABQAAA=",
        ] {
            let gz = base64::engine::general_purpose::STANDARD.decode(fixture).unwrap();
            let members = run_reader(flate2::read::MultiGzDecoder::new(gz.as_slice())).unwrap();
            let (member, data) = &members[0];
            assert_eq!(describe(member), "f 0");
            assert!(matches!(member.kind, Kind::Reg(size) if size == 1 << 20));
            assert_eq!(data.len(), 1 << 20);
            assert_eq!(&data[..4], b"head");
            assert_eq!(data[data.len() - 1], b'x');
            assert!(data[4..data.len() - 1].iter().all(|&c| c == 0));
        }
    }

    #[test]
    fn pax_sparse_0_0_maps_must_cover_the_data() {
        let sparse = |numbytes: &[u8]| {
            let records = [
                ("GNU.sparse.size", b"10".as_slice()),
                ("GNU.sparse.numblocks", b"1"),
                ("GNU.sparse.offset", b"4"),
                ("GNU.sparse.numbytes", numbytes),
            ];
            let pax: Vec<u8> = records
                .iter()
                .flat_map(|(k, v)| pax_record(k.as_bytes(), v))
                .collect();
            t().raw(XHEADER, b"PaxHeader", b"", 0o644, &pax)
                .raw(REG, b"s", b"", 0o644, b"ab")
                .finish()
        };
        let members = run(&sparse(b"2")).unwrap();
        assert_eq!(members[0].1, b"\0\0\0\0ab\0\0\0\0");
        let err = run(&sparse(b"1")).err().expect("must fail");
        assert!(
            err.report().to_string().contains("unreferenced"),
            "{}",
            err.report()
        );
    }

    #[test]
    fn truncated_members_fail() {
        let tar = t().reg("f").finish();
        assert!(run(&tar[..BLOCK]).is_err());
        assert!(
            run(&tar[..BLOCK + 1]).is_ok(),
            "missing padding ends the archive"
        );
    }

    #[test]
    fn numbers_parse_like_go() {
        assert_eq!(parse_numeric(b"0000644\0").unwrap(), 0o644);
        assert_eq!(parse_numeric(&[0x80, 0, 0, 0, 0, 0, 0, 42]).unwrap(), 42);
        assert_eq!(parse_numeric(&[0xff; 8]).unwrap(), -1);
        assert!(parse_numeric(b"0009\0").is_err());
        assert_eq!(
            parse_pax_time(b"1350244992.023960108"),
            Some((1350244992, 23960108))
        );
        assert_eq!(parse_pax_time(b"1."), Some((1, 0)));
        assert_eq!(parse_pax_time(b"+1"), Some((1, 0)));
        assert_eq!(parse_pax_time(b"-1.3"), Some((-2, 700_000_000)));
        assert_eq!(parse_pax_time(b"-0.1"), Some((-1, 900_000_000)));
        for invalid in ["", ".5", "-", "+", "-1.-1", "foo", "0.123456789abcdef"] {
            assert_eq!(parse_pax_time(invalid.as_bytes()), None, "{invalid}");
        }
        assert_eq!(bound_time((-1, 0)), (0, 0));
        assert_eq!(bound_time(MAX_TIME), (MAX_TIME.0 as u64, MAX_TIME.1));
        assert_eq!(bound_time((MAX_TIME.0, MAX_TIME.1 + 1)), (0, 0));
    }
}
