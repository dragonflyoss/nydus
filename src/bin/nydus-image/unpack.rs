use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Cursor, Error, ErrorKind, Read},
    iter::{self, from_fn, repeat},
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    rc::Rc,
    str,
    sync::Arc,
    vec::IntoIter,
};

use anyhow::{Context, Result};
use nydus_api::http::LocalFsConfig;
use nydus_rafs::{
    metadata::{RafsInode, RafsMode, RafsSuper},
    RafsIoReader,
};
use nydus_utils::compress::{self, Algorithm};
use storage::{
    backend::{localfs::LocalFs, BlobBackend, BlobReader},
    device::{BlobChunkInfo, BlobInfo},
    utils::alloc_buf,
};
use tar::{Builder, EntryType, Header};

use crate::core::node::InodeWrapper;

static PAX_SEP1: &[u8; 1] = b" ";
static PAX_SEP2: &[u8; 1] = b"=";
static PAX_PREFIX: &[u8; 13] = b"SCHILY.xattr.";
static PAX_DELIMITER: &[u8; 1] = b"\n";

pub trait Unpacker {
    fn unpack(&self) -> Result<()>;
}

///  A unpacker with the ability to convert bootstrap file and blob file to tar
pub struct OCIUnpacker {
    bootstrap: PathBuf,
    blob: Option<PathBuf>,
    output: PathBuf,

    builder_factory: OCITarBuilderFactory,
}

impl OCIUnpacker {
    pub fn new(bootstrap: &str, blob: Option<&str>, output: &str) -> Result<Self> {
        let bootstrap = PathBuf::from(bootstrap);
        let output = PathBuf::from(output);
        let blob = blob.map(PathBuf::from);

        let builder_factory = OCITarBuilderFactory::new();

        Ok(OCIUnpacker {
            builder_factory,
            bootstrap,
            blob,
            output,
        })
    }

    fn load_rafs(&self) -> Result<RafsSuper> {
        let bootstrap = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&*self.bootstrap)
            .with_context(|| format!("fail to open bootstrap {:?}", self.bootstrap))?;

        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: false,
            ..Default::default()
        };

        rs.load(&mut (Box::new(bootstrap) as RafsIoReader))
            .with_context(|| format!("fail to load bootstrap {:?}", self.bootstrap))?;

        Ok(rs)
    }

    /// A lazy iterator of RafsInode in DFS, which travels in preorder.
    fn iterator<'a>(
        &'a self,
        rs: &'a RafsSuper,
    ) -> Box<impl Iterator<Item = (Arc<dyn RafsInode>, PathBuf)> + 'a> {
        // A cursor means the next node to be visited at same height in the tree.
        // It always starts with the first one of level.
        // A cursor stack is of cursors from root to leaf.
        let mut cursor_stack = Vec::with_capacity(32);

        cursor_stack.push(self.cursor_of_root(rs));

        let dfs = move || {
            while !cursor_stack.is_empty() {
                let mut cursor = cursor_stack.pop().unwrap();

                let (node, path) = match cursor.next() {
                    None => continue,
                    Some(point) => {
                        cursor_stack.push(cursor);
                        point
                    }
                };

                if node.is_dir() {
                    cursor_stack.push(self.cursor_of_children(node.clone(), &*path))
                }

                return Some((node, path));
            }

            None
        };

        Box::new(from_fn(dfs))
    }

    fn cursor_of_children(
        &self,
        node: Arc<dyn RafsInode>,
        path: &Path,
    ) -> Box<dyn Iterator<Item = (Arc<dyn RafsInode>, PathBuf)>> {
        let base = path.to_path_buf();
        let mut next_idx = 0..node.get_child_count();

        let visitor = move || {
            if next_idx.is_empty() {
                return None;
            }

            let child = node.get_child_by_index(next_idx.next().unwrap()).unwrap();
            let child_path = base.join(child.name());

            Some((child, child_path))
        };

        Box::new(from_fn(visitor))
    }

    fn cursor_of_root<'a>(
        &self,
        rs: &'a RafsSuper,
    ) -> Box<dyn Iterator<Item = (Arc<dyn RafsInode>, PathBuf)> + 'a> {
        let mut has_more = true;
        let visitor = from_fn(move || {
            if !has_more {
                return None;
            }
            has_more = false;

            let node = rs.get_inode(rs.superblock.root_ino(), false).unwrap();
            let path = PathBuf::from("/").join(node.name());

            Some((node, path))
        });

        Box::new(visitor)
    }
}

impl Unpacker for OCIUnpacker {
    fn unpack(&self) -> Result<()> {
        info!(
            "oci unpacker, bootstrap file: {:?}, blob file: {:?}, output file: {:?}",
            self.bootstrap, self.blob, self.output
        );

        let rafs = self.load_rafs()?;

        let mut builder = self
            .builder_factory
            .create(&rafs, self.blob.as_deref(), &self.output)?;

        for (node, path) in self.iterator(&rafs) {
            if Util::is_root(&path) {
                continue;
            }
            builder.append(&*node, &path)?;
        }

        Ok(())
    }
}

trait TarBuilder {
    fn append(&mut self, node: &dyn RafsInode, path: &Path) -> Result<()>;
}

struct TarSection {
    header: Header,
    data: Box<dyn Read>,
}

trait SectionBuilder {
    fn can_handle(&mut self, inode: &dyn RafsInode, path: &Path) -> bool;
    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>>;
}

struct OCISocketBuilder {}

impl OCISocketBuilder {
    fn new() -> Self {
        OCISocketBuilder {}
    }
}

impl SectionBuilder for OCISocketBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_sock()
    }

    fn build(&self, _: &dyn RafsInode, _: &Path) -> Result<Vec<TarSection>> {
        Ok(Vec::new())
    }
}

struct OCILinkBuilder {
    links: HashMap<u64, Box<Path>>,
    pax_link_builder: Rc<PAXLinkBuilder>,
}

impl OCILinkBuilder {
    fn new(pax_link_builder: Rc<PAXLinkBuilder>) -> Self {
        OCILinkBuilder {
            links: HashMap::new(),
            pax_link_builder,
        }
    }
}

impl SectionBuilder for OCILinkBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, path: &Path) -> bool {
        if !node.is_hardlink() || node.is_dir() {
            return false;
        }

        let is_appeared = self.links.contains_key(&node.ino());
        if !is_appeared {
            self.links
                .insert(node.ino(), path.to_path_buf().into_boxed_path());
        }

        is_appeared
    }

    fn build(&self, node: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        let link = self.links.get(&node.ino()).unwrap();

        self.pax_link_builder
            .build(EntryType::hard_link(), node, path, link)
    }
}

struct OCIDirBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl OCIDirBuilder {
    fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        OCIDirBuilder { ext_builder }
    }
}

impl SectionBuilder for OCIDirBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        node.is_dir()
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::dir());
        header.set_size(0);
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(Util::mask_mode(node.mode()));

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
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

struct OCIRegBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
    reader: Option<Arc<dyn BlobReader>>,
    compressor: Option<Algorithm>,
}

impl OCIRegBuilder {
    fn new(
        ext_builder: Rc<PAXExtensionSectionBuilder>,
        reader: Option<Arc<dyn BlobReader>>,
        compressor: Option<Algorithm>,
    ) -> Self {
        OCIRegBuilder {
            ext_builder,
            reader,
            compressor,
        }
    }

    fn build_data(&self, inode: &dyn RafsInode) -> Box<dyn Read> {
        if self.reader.is_none() {
            return Box::new(io::empty());
        }

        let chunks = (0..inode.get_chunk_count())
            .map(|i| inode.get_chunk_info(i).unwrap())
            .collect();

        let reader = ChunkReader::new(
            *self.compressor.as_ref().unwrap(),
            self.reader.as_ref().unwrap().clone(),
            chunks,
        );

        Box::new(reader)
    }
}

impl SectionBuilder for OCIRegBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        node.is_reg()
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::file());
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(Util::mask_mode(node.mode()));
        header.set_size(node.size());

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        Util::set_cksum(&mut header);

        let mut sections = Vec::with_capacity(2);
        if let Some(ext_sect) = self.ext_builder.build(&header, extensions)? {
            sections.push(ext_sect);
        }

        let main_header = TarSection {
            header,
            data: Box::new(self.build_data(inode)),
        };
        sections.push(main_header);

        Ok(sections)
    }
}

struct OCISymlinkBuilder {
    pax_link_builder: Rc<PAXLinkBuilder>,
}

impl OCISymlinkBuilder {
    fn new(pax_link_builder: Rc<PAXLinkBuilder>) -> Self {
        OCISymlinkBuilder { pax_link_builder }
    }
}

impl SectionBuilder for OCISymlinkBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        node.is_symlink()
    }

    fn build(&self, node: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        let link = node.get_symlink().unwrap();

        self.pax_link_builder
            .build(EntryType::symlink(), node, path, &PathBuf::from(link))
    }
}

struct OCIFifoBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCIFifoBuilder {
    fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCIFifoBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCIFifoBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_fifo()
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::fifo(), inode, path)
    }
}

struct OCICharBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCICharBuilder {
    fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCICharBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCICharBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_chrdev()
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::character_special(), inode, path)
    }
}

struct OCIBlockBuilder {
    pax_special_builder: Rc<PAXSpecialSectionBuilder>,
}

impl OCIBlockBuilder {
    fn new(pax_special_builder: Rc<PAXSpecialSectionBuilder>) -> Self {
        OCIBlockBuilder {
            pax_special_builder,
        }
    }
}

impl SectionBuilder for OCIBlockBuilder {
    fn can_handle(&mut self, node: &dyn RafsInode, _: &Path) -> bool {
        InodeWrapper::from_inode_info(node).is_blkdev()
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        self.pax_special_builder
            .build(EntryType::block_special(), inode, path)
    }
}

struct PAXSpecialSectionBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl PAXSpecialSectionBuilder {
    fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        PAXSpecialSectionBuilder { ext_builder }
    }

    fn build(
        &self,
        entry_type: EntryType,
        inode: &dyn RafsInode,
        path: &Path,
    ) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(Util::mask_mode(node.mode()));
        header.set_size(node.size());

        let dev_id = self.cal_dev(inode.rdev() as u64);
        header.set_device_major(dev_id.0)?;
        header.set_device_minor(dev_id.1)?;

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
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

struct PAXExtensionSectionBuilder {}

impl PAXExtensionSectionBuilder {
    fn new() -> Self {
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

struct PAXLinkBuilder {
    ext_builder: Rc<PAXExtensionSectionBuilder>,
}

impl PAXLinkBuilder {
    fn new(ext_builder: Rc<PAXExtensionSectionBuilder>) -> Self {
        PAXLinkBuilder { ext_builder }
    }

    fn build(
        &self,
        entry_type: EntryType,
        inode: &dyn RafsInode,
        path: &Path,
        link: &Path,
    ) -> Result<Vec<TarSection>> {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(Util::mask_mode(node.mode()));

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::set_link(&mut header, link)? {
            extensions.push(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
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
    fn get_xattr_as_extensions(inode: &dyn RafsInode) -> Option<Vec<PAXRecord>> {
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
        let path = Util::normalize_path(path).with_context(|| "fail to normalize path")?;

        let max_len = header.as_old().linkname.len();
        if path.as_os_str().len() <= max_len {
            return header
                .set_link_name(&path)
                .with_context(|| "fail to set short link for pax header")
                .map(|_| None);
        }

        let extension = PAXRecord {
            k: "linkpath".to_owned().into_bytes(),
            v: path.to_owned().into_os_string().into_vec(),
        };

        let path = Util::truncate_path(&path, max_len)
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

struct Util {}

impl Util {
    fn is_root(path: &Path) -> bool {
        path.is_absolute() && path.file_name().is_none()
    }

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

struct OCITarBuilderFactory {}

impl OCITarBuilderFactory {
    fn new() -> Self {
        OCITarBuilderFactory {}
    }

    fn create(
        &self,
        meta: &RafsSuper,
        blob_path: Option<&Path>,
        output_path: &Path,
    ) -> Result<Box<dyn TarBuilder>> {
        let writer = self.create_writer(output_path)?;

        let blob = meta.superblock.get_blob_infos().pop();
        let builders = self.create_builders(blob, blob_path)?;

        let builder = OCITarBuilder::new(builders, writer);

        Ok(Box::new(builder) as Box<dyn TarBuilder>)
    }

    fn create_writer(&self, output_path: &Path) -> Result<Builder<File>> {
        let builder = Builder::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .read(false)
                .open(output_path)
                .with_context(|| format!("fail to open output file {:?}", output_path))?,
        );

        Ok(builder)
    }

    fn create_builders(
        &self,
        blob: Option<Arc<BlobInfo>>,
        blob_path: Option<&Path>,
    ) -> Result<Vec<Box<dyn SectionBuilder>>> {
        // PAX basic builders
        let ext_builder = Rc::new(PAXExtensionSectionBuilder::new());
        let link_builder = Rc::new(PAXLinkBuilder::new(ext_builder.clone()));
        let special_builder = Rc::new(PAXSpecialSectionBuilder::new(ext_builder.clone()));

        // OCI builders
        let sock_builder = OCISocketBuilder::new();
        let hard_link_builder = OCILinkBuilder::new(link_builder.clone());
        let symlink_builder = OCISymlinkBuilder::new(link_builder);
        let dir_builder = OCIDirBuilder::new(ext_builder);
        let fifo_builder = OCIFifoBuilder::new(special_builder.clone());
        let char_builder = OCICharBuilder::new(special_builder.clone());
        let block_builder = OCIBlockBuilder::new(special_builder);
        let reg_builder = self.create_reg_builder(blob, blob_path)?;

        // The order counts.
        let builders = vec![
            Box::new(sock_builder) as Box<dyn SectionBuilder>,
            Box::new(hard_link_builder),
            Box::new(dir_builder),
            Box::new(reg_builder),
            Box::new(symlink_builder),
            Box::new(fifo_builder),
            Box::new(char_builder),
            Box::new(block_builder),
        ];

        Ok(builders)
    }

    fn create_reg_builder(
        &self,
        blob: Option<Arc<BlobInfo>>,
        blob_path: Option<&Path>,
    ) -> Result<OCIRegBuilder> {
        let (reader, compressor) = match blob {
            None => (None, None),
            Some(ref blob) => {
                if blob_path.is_none() {
                    bail!("miss blob path")
                }

                let reader = self.create_blob_reader(blob_path.unwrap())?;
                let compressor = blob.compressor();

                (Some(reader), Some(compressor))
            }
        };

        Ok(OCIRegBuilder::new(
            Rc::new(PAXExtensionSectionBuilder::new()),
            reader,
            compressor,
        ))
    }

    fn create_blob_reader(&self, blob_path: &Path) -> Result<Arc<dyn BlobReader>> {
        let config = LocalFsConfig {
            blob_file: blob_path.to_str().unwrap().to_owned(),
            readahead: false,
            readahead_sec: Default::default(),
            dir: Default::default(),
            alt_dirs: Default::default(),
        };
        let config = serde_json::to_value(config)
            .with_context(|| format!("fail to create local backend config for {:?}", blob_path))?;

        let backend = LocalFs::new(config, Some("unpacker"))
            .with_context(|| format!("fail to create local backend for {:?}", blob_path))?;

        let reader = backend
            .get_reader("")
            .map_err(|err| anyhow!("fail to get reader, error {:?}", err))?;

        Ok(reader)
    }
}

struct OCITarBuilder {
    writer: Builder<File>,
    builders: Vec<Box<dyn SectionBuilder>>,
}

impl OCITarBuilder {
    fn new(builders: Vec<Box<dyn SectionBuilder>>, writer: Builder<File>) -> Self {
        Self { builders, writer }
    }
}

impl TarBuilder for OCITarBuilder {
    fn append(&mut self, inode: &dyn RafsInode, path: &Path) -> Result<()> {
        let mut is_known_type = true;

        for builder in &mut self.builders {
            // Useless one, just go !!!!!
            if !builder.can_handle(inode, path) {
                continue;
            }

            for sect in builder.build(inode, path)? {
                self.writer.append(&sect.header, sect.data)?;
            }

            is_known_type = false;

            break;
        }

        if is_known_type {
            bail!("node {:?} can not be unpacked", path)
        }

        Ok(())
    }
}

struct ChunkReader {
    compressor: Algorithm,
    reader: Arc<dyn BlobReader>,

    chunks: IntoIter<Arc<dyn BlobChunkInfo>>,
    chunk: Cursor<Vec<u8>>,
}

impl ChunkReader {
    fn new(
        compressor: Algorithm,
        reader: Arc<dyn BlobReader>,
        chunks: Vec<Arc<dyn BlobChunkInfo>>,
    ) -> Self {
        Self {
            compressor,
            reader,
            chunks: chunks.into_iter(),
            chunk: Cursor::new(Vec::new()),
        }
    }

    fn load_chunk(&mut self, chunk: &dyn BlobChunkInfo) -> Result<()> {
        let mut buf = alloc_buf(chunk.compress_size() as usize);
        self.reader
            .read(buf.as_mut_slice(), chunk.compress_offset())
            .map_err(|err| {
                error!("fail to read chunk, error: {:?}", err);
                anyhow!("fail to read chunk, error: {:?}", err)
            })?;

        if !chunk.is_compressed() {
            self.chunk = Cursor::new(buf);
            return Ok(());
        }

        let mut data = vec![0u8; chunk.uncompress_size() as usize];
        compress::decompress(
            buf.as_mut_slice(),
            None,
            data.as_mut_slice(),
            self.compressor,
        )
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
                let chunk = self.chunks.next();
                if chunk.is_none() {
                    break;
                }

                self.load_chunk(chunk.unwrap().as_ref()).map_err(|err| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("fail to load chunk, error: {}", err),
                    )
                })?;
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
