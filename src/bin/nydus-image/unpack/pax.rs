use nix::unistd::{Gid, Group, Uid, User};
use std::ops::Deref;
use std::{
    collections::HashMap,
    ffi::OsStr,
    io::{self, Cursor, Error, ErrorKind, Read},
    iter::{self, repeat},
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    rc::Rc,
    str,
    sync::Arc,
    vec::IntoIter,
};

use anyhow::{Context, Result};
use nydus_rafs::metadata::inode::InodeWrapper;
use nydus_rafs::metadata::RafsInodeExt;
use nydus_storage::{backend::BlobReader, device::BlobChunkInfo, utils::alloc_buf};
use nydus_utils::compress::{self, Algorithm};
use tar::{EntryType, Header};

use super::{SectionBuilder, TarSection};

static PAX_SEP1: &[u8; 1] = b" ";
static PAX_SEP2: &[u8; 1] = b"=";
static PAX_PREFIX: &[u8; 13] = b"SCHILY.xattr.";
static PAX_DELIMITER: &[u8; 1] = b"\n";

pub struct OCISocketBuilder {}

impl OCISocketBuilder {
    pub fn new() -> Self {
        OCISocketBuilder {}
    }
}

impl SectionBuilder for OCISocketBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_sock()
    }

    fn build(&self, _: Arc<dyn RafsInodeExt>, _: &Path) -> Result<Vec<TarSection>> {
        Ok(Vec::new())
    }
}

pub struct OCILinkBuilder {
    links: HashMap<u64, PathBuf>,
    pax_link_builder: Rc<PAXLinkBuilder>,
}

impl OCILinkBuilder {
    pub fn new(pax_link_builder: Rc<PAXLinkBuilder>) -> Self {
        OCILinkBuilder {
            links: HashMap::new(),
            pax_link_builder,
        }
    }
}

impl SectionBuilder for OCILinkBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, path: &Path) -> bool {
        if !node.is_hardlink() || node.is_dir() {
            return false;
        }

        let is_appeared = self.links.contains_key(&node.ino());
        if !is_appeared {
            self.links.insert(node.ino(), path.to_path_buf());
        }

        is_appeared
    }

    fn build(&self, node: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        let link = self.links.get(&node.ino()).unwrap();

        self.pax_link_builder
            .build(EntryType::hard_link(), node, path, link)
    }
}

pub struct OCIDirBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl OCIDirBuilder {
    pub fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        OCIDirBuilder { ext_builder }
    }

    fn is_root(&self, path: &Path) -> bool {
        path.is_absolute() && path.file_name().is_none()
    }
}

fn set_header_by_inode(inode: Arc<dyn RafsInodeExt>, header: &mut Header) -> Result<()> {
    let inode = InodeWrapper::from_inode_info(inode);
    header.set_size(inode.size());
    header.set_mtime(inode.mtime());
    header.set_uid(inode.uid() as u64);
    header.set_gid(inode.gid() as u64);

    // To make the unpacked tar consistent with the OCI-formatted tar before the pack,
    // we need to backfill the username and groupname in the tar header, which may
    // break the repeatable build when unpacking in different hosts, but actually has
    // little effect.
    let username = User::from_uid(Uid::from_raw(inode.uid()))
        .unwrap_or(None)
        .map(|user| user.name)
        .unwrap_or_default();
    header.set_username(&username)?;
    let groupname = Group::from_gid(Gid::from_raw(inode.gid()))
        .unwrap_or(None)
        .map(|group| group.name)
        .unwrap_or_default();
    header.set_groupname(&groupname)?;

    header.set_mode(Util::mask_mode(inode.mode()));

    Ok(())
}

impl SectionBuilder for OCIDirBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        node.is_dir()
    }

    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        if self.is_root(path) {
            return Ok(Vec::new());
        }

        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::dir());
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();

        set_header_by_inode(inode.clone(), &mut header)?;
        header.set_size(0);

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode.deref()) {
            extensions.extend(extension);
        }

        Util::set_cksum(&mut header);

        let mut sections = Vec::with_capacity(2);
        if let Some(ext_sect) = self.ext_builder.build(&header, extensions)? {
            sections.push(ext_sect);
        }

        let main_header = TarSection {
            header,
            data: Box::new(io::empty()),
        };
        sections.push(main_header);

        Ok(sections)
    }
}

pub struct OCIRegBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
    readers: HashMap<u32, Arc<dyn BlobReader>>,
    compressors: HashMap<u32, Algorithm>,
}

impl OCIRegBuilder {
    pub fn new(
        ext_builder: Rc<PAXExtensionSectionBuilder>,
        readers: HashMap<u32, Arc<dyn BlobReader>>,
        compressors: HashMap<u32, Algorithm>,
    ) -> Self {
        OCIRegBuilder {
            ext_builder,
            readers,
            compressors,
        }
    }

    fn build_data(&self, inode: &dyn RafsInodeExt) -> Box<dyn Read> {
        let chunks = (0..inode.get_chunk_count())
            .map(|i| inode.get_chunk_info(i).unwrap())
            .collect();

        let mut compressors = HashMap::new();
        compressors.clone_from(&self.compressors);

        let mut readers = HashMap::new();
        readers.clone_from(&self.readers);
        let reader = ChunkReader::new(compressors, readers, chunks);

        Box::new(reader)
    }
}

impl SectionBuilder for OCIRegBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        node.is_reg()
    }

    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::file());
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();
        set_header_by_inode(inode.clone(), &mut header)?;

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode.deref()) {
            extensions.extend(extension);
        }

        Util::set_cksum(&mut header);

        let mut sections = Vec::with_capacity(2);
        if let Some(ext_sect) = self.ext_builder.build(&header, extensions)? {
            sections.push(ext_sect);
        }

        let main_header = TarSection {
            header,
            data: Box::new(self.build_data(inode.deref())),
        };
        sections.push(main_header);

        Ok(sections)
    }
}

pub struct OCISymlinkBuilder {
    pax_link_builder: Rc<PAXLinkBuilder>,
}

impl OCISymlinkBuilder {
    pub fn new(pax_link_builder: Rc<PAXLinkBuilder>) -> Self {
        OCISymlinkBuilder { pax_link_builder }
    }
}

impl SectionBuilder for OCISymlinkBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        node.is_symlink()
    }

    fn build(&self, node: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        let link = node.get_symlink().unwrap();

        self.pax_link_builder
            .build(EntryType::symlink(), node, path, &PathBuf::from(link))
    }
}

pub struct OCIFifoBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCIFifoBuilder {
    pub fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCIFifoBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCIFifoBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_fifo()
    }

    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::fifo(), inode, path)
    }
}

pub struct OCICharBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCICharBuilder {
    pub fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCICharBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCICharBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_chrdev()
    }

    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::character_special(), inode, path)
    }
}

pub struct OCIBlockBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCIBlockBuilder {
    pub fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCIBlockBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCIBlockBuilder {
    fn can_handle(&mut self, node: Arc<dyn RafsInodeExt>, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_blkdev()
    }

    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::block_special(), inode, path)
    }
}

pub struct PAXSpecialSectionBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl PAXSpecialSectionBuilder {
    pub fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        PAXSpecialSectionBuilder { ext_builder }
    }

    fn build(
        &self,
        entry_type: EntryType,
        inode: Arc<dyn RafsInodeExt>,
        path: &Path,
    ) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);
        set_header_by_inode(inode.clone(), &mut header)?;

        let dev_id = self.cal_dev(inode.rdev() as u64);
        header.set_device_major(dev_id.0)?;
        header.set_device_minor(dev_id.1)?;

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode.deref()) {
            extensions.extend(extension);
        }

        Util::set_cksum(&mut header);

        let mut sections = Vec::with_capacity(2);
        if let Some(ext_sect) = self.ext_builder.build(&header, extensions)? {
            sections.push(ext_sect);
        }

        let main_header = TarSection {
            header,
            data: Box::new(io::empty()),
        };
        sections.push(main_header);

        Ok(sections)
    }

    fn cal_dev(&self, dev_id: u64) -> (u32, u32) {
        let major = ((dev_id >> 32) & 0xffff_f000) | ((dev_id >> 8) & 0x0000_0fff);
        let minor = ((dev_id >> 12) & 0xffff_ff00) | ((dev_id) & 0x0000_00ff);

        (major as u32, minor as u32)
    }
}

struct PAXRecord {
    k: Vec<u8>,
    v: Vec<u8>,
}

pub struct PAXExtensionSectionBuilder {}

impl PAXExtensionSectionBuilder {
    pub fn new() -> Self {
        PAXExtensionSectionBuilder {}
    }

    fn build(&self, header: &Header, extensions: Vec<PAXRecord>) -> Result<Option<TarSection>> {
        if extensions.is_empty() {
            return Ok(None);
        }

        let path = header.path().unwrap().into_owned();

        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);

        let data = self.build_data(extensions);
        header.set_size(data.len() as u64);

        header
            .set_path(&self.build_pax_name(&path, header.as_old().name.len())?)
            .with_context(|| "fail to set path for pax section")?;

        Util::set_cksum(&mut header);

        Ok(Some(TarSection {
            header,
            data: Box::new(Cursor::new(data)),
        }))
    }

    fn build_data(&self, mut extensions: Vec<PAXRecord>) -> Vec<u8> {
        extensions.sort_by(|r1, r2| {
            let k1 = str::from_utf8(&r1.k).unwrap();
            let k2 = str::from_utf8(&r2.k).unwrap();
            k1.cmp(k2)
        });

        extensions
            .into_iter()
            .flat_map(|r| self.build_pax_record(&r.k, &r.v))
            .collect()
    }

    fn build_pax_name(&self, path: &Path, max_len: usize) -> Result<PathBuf> {
        let filename = path.file_name().unwrap().to_owned();

        let mut path = path.to_path_buf();
        path.set_file_name("PaxHeaders.0");
        let mut path = path.join(filename);

        if path.as_os_str().len() > max_len {
            path = Util::truncate_path(&path, max_len)?;
        }

        Ok(path)
    }

    fn build_pax_record(&self, k: &[u8], v: &[u8]) -> Vec<u8> {
        fn pax(buf: &mut Vec<u8>, size: usize, k: &[u8], v: &[u8]) {
            buf.extend_from_slice(size.to_string().as_bytes());
            buf.extend_from_slice(PAX_SEP1);
            buf.extend_from_slice(k);
            buf.extend_from_slice(PAX_SEP2);
            buf.extend_from_slice(v);
            buf.extend_from_slice(PAX_DELIMITER);
        }

        let mut size = k.len() + v.len() + PAX_SEP1.len() + PAX_SEP2.len() + PAX_DELIMITER.len();
        size += size.to_string().as_bytes().len();

        let mut record = Vec::with_capacity(size);
        pax(&mut record, size, k, v);

        if record.len() != size {
            size = record.len();
            record.clear();
            pax(&mut record, size, k, v);
        }

        record
    }
}

pub struct PAXLinkBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl PAXLinkBuilder {
    pub fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        PAXLinkBuilder { ext_builder }
    }

    fn build(
        &self,
        entry_type: EntryType,
        inode: Arc<dyn RafsInodeExt>,
        path: &Path,
        link: &Path,
    ) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        set_header_by_inode(inode.clone(), &mut header)?;
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::set_link(&mut header, link)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode.deref()) {
            extensions.extend(extension);
        }

        Util::set_cksum(&mut header);

        let mut sections = Vec::with_capacity(2);
        if let Some(ext_sect) = self.ext_builder.build(&header, extensions)? {
            sections.push(ext_sect);
        }

        let main_header = TarSection {
            header,
            data: Box::new(io::empty()),
        };
        sections.push(main_header);

        Ok(sections)
    }
}

struct PAXUtil {}

impl PAXUtil {
    fn get_xattr_as_extensions(inode: &dyn RafsInodeExt) -> Option<Vec<PAXRecord>> {
        if !inode.has_xattr() {
            return None;
        }

        let keys = inode.get_xattrs().unwrap();
        let mut extensions = Vec::with_capacity(keys.len());

        for key in keys {
            let value = inode
                .get_xattr(OsStr::from_bytes(&key))
                .unwrap()
                .unwrap_or_default();

            let key = Vec::from(PAX_PREFIX.to_owned())
                .into_iter()
                .chain(key.into_iter())
                .collect();
            extensions.push(PAXRecord { k: key, v: value });
        }

        Some(extensions)
    }

    fn set_link(header: &mut Header, path: &Path) -> Result<Option<PAXRecord>> {
        let max_len = header.as_old().linkname.len();
        if path.as_os_str().len() <= max_len {
            return header
                .set_link_name(path)
                .with_context(|| "fail to set short link for pax header")
                .map(|_| None);
        }

        let extension = PAXRecord {
            k: "linkpath".to_owned().into_bytes(),
            v: path.to_owned().into_os_string().into_vec(),
        };

        let path = Util::truncate_path(path, max_len)
            .with_context(|| "fail to truncate link for pax header")?;

        header
            .set_link_name(&path)
            .with_context(|| format!("fail to set header link again for {:?}", path))?;

        Ok(Some(extension))
    }

    fn set_path(header: &mut Header, path: &Path) -> Result<Option<PAXRecord>> {
        let path = Util::normalize_path(path).with_context(|| "fail to normalize path")?;

        let max_len = header.as_old().name.len();
        if path.as_os_str().len() <= max_len {
            return header
                .set_path(path)
                .with_context(|| "fail to set short path for pax header")
                .map(|_| None);
        }

        let extension = PAXRecord {
            k: "path".to_owned().into_bytes(),
            v: path.to_owned().into_os_string().into_vec(),
        };

        let path = Util::truncate_path(&path, max_len)
            .with_context(|| "fail to truncate path for pax header")?;

        header
            .set_path(&path)
            .with_context(|| format!("fail to set header path again for {:?}", path))?;

        Ok(Some(extension))
    }
}

pub struct Util {}

impl Util {
    fn normalize_path(path: &Path) -> Result<PathBuf> {
        fn end_with_slash(p: &Path) -> bool {
            p.as_os_str().as_bytes().last() == Some(&b'/')
        }

        let mut normalized = if path.has_root() {
            path.strip_prefix("/")
                .with_context(|| "fail to strip prefix /")?
                .to_path_buf()
        } else {
            path.to_path_buf()
        };

        if end_with_slash(&normalized) {
            let name = normalized.file_name().unwrap().to_owned();
            normalized.set_file_name(name);
        }

        Ok(normalized)
    }

    // path is required longer than max_len
    fn truncate_path(path: &Path, max_len: usize) -> Result<PathBuf> {
        let path = path.as_os_str().as_bytes();
        if path.len() < max_len {
            bail!("path is shorter than limit")
        }

        let path = match str::from_utf8(&path[..max_len]) {
            Ok(s) => Ok(s),
            Err(err) => str::from_utf8(&path[..err.valid_up_to()])
                .with_context(|| "fail to convert bytes to utf8 str"),
        }?;

        Ok(PathBuf::from(path))
    }

    // Common Unix mode constants; these are not defined in any common tar standard.
    //
    //    c_ISDIR  = 040000  // Directory
    //    c_ISFIFO = 010000  // FIFO
    //    c_ISREG  = 0100000 // Regular file
    //    c_ISLNK  = 0120000 // Symbolic link
    //    c_ISBLK  = 060000  // Block special file
    //    c_ISCHR  = 020000  // Character special file
    //    c_ISSOCK = 0140000 // Socket
    //
    // Although many readers bear it, such as Go standard library and tar tool in ubuntu
    // Truncate to last four bytes. The four consists of below:
    //
    //    c_ISUID = 04000 // Set uid
    //    c_ISGID = 02000 // Set gid
    //    c_ISVTX = 01000 // Sticky bit
    //    MODE_PERM = 0777 // Owner:Group:Other R/W
    fn mask_mode(st_mode: u32) -> u32 {
        st_mode & 0o7777
    }

    // The checksum is calculated by taking the sum of the unsigned byte values of
    // the header record with the eight checksum bytes taken to be ASCII spaces (decimal value 32).
    // It is stored as a six digit octal number with leading zeroes followed by a NUL and then a space.
    // The wiki and Go standard library adhere to this format. Stay with them~~~.
    fn set_cksum(header: &mut Header) {
        let old = header.as_old();
        let start = old as *const _ as usize;
        let cksum_start = old.cksum.as_ptr() as *const _ as usize;
        let offset = cksum_start - start;
        let len = old.cksum.len();

        let bs = header.as_bytes();
        let sum = bs[0..offset]
            .iter()
            .chain(iter::repeat(&b' ').take(len))
            .chain(&bs[offset + len..])
            .fold(0, |a, b| a + (*b as u32));

        let bs = &mut header.as_old_mut().cksum;
        bs[bs.len() - 1] = b' ';
        bs[bs.len() - 2] = 0o0;

        let o = format!("{:o}", sum);
        let value = o.bytes().rev().chain(repeat(b'0'));
        for (slot, value) in bs.iter_mut().rev().skip(2).zip(value) {
            *slot = value;
        }
    }
}

struct ChunkReader {
    compressors: HashMap<u32, Algorithm>,
    readers: HashMap<u32, Arc<dyn BlobReader>>,

    chunks: IntoIter<Arc<dyn BlobChunkInfo>>,
    chunk: Cursor<Vec<u8>>,
}

impl ChunkReader {
    fn new(
        compressors: HashMap<u32, Algorithm>,
        readers: HashMap<u32, Arc<dyn BlobReader>>,
        chunks: Vec<Arc<dyn BlobChunkInfo>>,
    ) -> Self {
        Self {
            compressors,
            readers,
            chunks: chunks.into_iter(),
            chunk: Cursor::new(Vec::new()),
        }
    }

    fn load_chunk(&mut self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        let mut buf = alloc_buf(chunk.compressed_size() as usize);

        let reader = self
            .readers
            .get(&chunk.blob_index())
            .expect("No valid reader")
            .clone();
        reader
            .read(buf.as_mut_slice(), chunk.compressed_offset())
            .map_err(|err| {
                error!("fail to read chunk, error: {:?}", err);
                anyhow!("fail to read chunk, error: {:?}", err)
            })?;

        if !chunk.is_compressed() {
            self.chunk = Cursor::new(buf);
            return Ok(());
        }

        let compressor = *self
            .compressors
            .get(&chunk.blob_index())
            .expect("No valid compressor");

        let mut data = vec![0u8; chunk.uncompressed_size() as usize];
        compress::decompress(buf.as_mut_slice(), data.as_mut_slice(), compressor)
            .with_context(|| "fail to decompress")?;

        self.chunk = Cursor::new(data);

        Ok(())
    }

    fn is_chunk_empty(&self) -> bool {
        self.chunk.position() >= self.chunk.get_ref().len() as u64
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut size = 0;

        loop {
            if self.is_chunk_empty() {
                match self.chunks.next() {
                    None => break,
                    Some(chunk) => self.load_chunk(chunk.as_ref()).map_err(|err| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("fail to load chunk, error: {}", err),
                        )
                    })?,
                }
            }

            size += Read::read(&mut self.chunk, &mut buf[size..])?;
            if size == buf.len() {
                break;
            }
        }

        Ok(size)
    }
}

#[cfg(test)]
mod test;
