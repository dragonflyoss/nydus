extern crate tar;

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Cursor, Error, ErrorKind, Read},
    iter::from_fn,
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    rc::Rc,
    str,
    sync::Arc,
    vec::IntoIter,
};

use anyhow::Result;
use nydus_rafs::{
    metadata::{layout::RAFS_ROOT_INODE, RafsInode, RafsMode, RafsSuper},
    RafsIoReader,
};
use nydus_utils::compress::{self, Algorithm};
use storage::{
    backend::{localfs::LocalFs, BlobBackend, BlobReader, LocalFsConfig},
    device::BlobChunkInfo,
    utils::alloc_buf,
};
use tar::{Builder, EntryType, Header};

use crate::core::node::{InodeWrapper, OCISPEC_WHITEOUT_PREFIX, ROOT_PATH_NAME};

static PAX_SEP1: &'static [u8; 1] = b" ";
static PAX_SEP2: &'static [u8; 1] = b"=";
static PAX_PREFIX: &'static [u8; 13] = b"SCHILY.xattr.";
static PAX_DELIMITER: &'static [u8; 1] = b"\n";

pub trait Decompressor {
    fn decompress(&self) -> Result<()>;
}

///  A decompressor with the ability to convert bootstrap file and blob file to tar
pub struct OCIDecompressor {
    bootstrap: Box<Path>,
    blob_dir: Option<Box<Path>>,
    output: Box<Path>,
}

impl OCIDecompressor {
    pub fn new(bootstrap: &str, blob_dir: Option<&str>, output: &str) -> Result<Self> {
        let bootstrap = PathBuf::from(bootstrap).into_boxed_path();
        let output = PathBuf::from(output).into_boxed_path();

        let blob_dir = match blob_dir {
            Some(dir) => Some(PathBuf::from(dir).canonicalize()?.into_boxed_path()),
            None => None,
        };

        Ok(OCIDecompressor {
            bootstrap,
            blob_dir,
            output,
        })
    }

    fn load_rafs(&self) -> Result<RafsSuper> {
        let bootstrap = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&*self.bootstrap)
            .map_err(|err| {
                error!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap, err
                );
                anyhow!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap,
                    err
                )
            })?;

        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };
        rs.load(&mut (Box::new(bootstrap) as RafsIoReader))
            .map_err(|err| {
                error!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap, err
                );
                anyhow!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap,
                    err
                )
            })?;

        Ok(rs)
    }

    /// A lazy iterator of RafsInode in DFS, which travels in preorder.
    fn iterator<'a>(
        &'a self,
        rs: &'a RafsSuper,
    ) -> Box<impl Iterator<Item = (Arc<dyn RafsInode>, Box<Path>)> + 'a> {
        // A cursor means the next node to visit of certain height in the tree. It always starts with the first one of level.
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
    ) -> Box<dyn Iterator<Item = (Arc<dyn RafsInode>, Box<Path>)>> {
        let base = path.to_path_buf();
        let mut next_idx = 0..node.get_child_count();

        let visitor = move || {
            if next_idx.is_empty() {
                return None;
            }

            let child = node.get_child_by_index(next_idx.next().unwrap()).unwrap();
            let child_path = base.join(child.name()).into_boxed_path();

            Some((child, child_path))
        };

        Box::new(from_fn(visitor))
    }

    fn cursor_of_root<'a>(
        &self,
        rs: &'a RafsSuper,
    ) -> Box<dyn Iterator<Item = (Arc<dyn RafsInode>, Box<Path>)> + 'a> {
        let mut has_more = true;
        let visitor = from_fn(move || {
            if !has_more {
                return None;
            }
            has_more = false;

            let node = rs.get_inode(RAFS_ROOT_INODE, false).unwrap();
            let path = PathBuf::from("/").join(node.name()).into_boxed_path();

            Some((node, path))
        });

        Box::new(visitor)
    }
}

impl Decompressor for OCIDecompressor {
    fn decompress(&self) -> Result<()> {
        info!(
            "default decompressor, bootstrap file: {:?}, blob file: {:?}, output file: {:?}",
            self.bootstrap, self.blob_dir, self.output
        );

        let rafs = self.load_rafs()?;

        let mut builder = Box::new(OCITarBuilder::new(
            &rafs,
            self.blob_dir.as_ref().map(|dir| dir.as_ref()),
            &*self.output,
        )?) as Box<dyn TarBuilder>;

        for (node, path) in self.iterator(&rafs) {
            if node.name() == OsStr::from_bytes(ROOT_PATH_NAME) {
                continue;
            }
            builder.append(&*node, &*path)?;
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

        return is_appeared;
    }

    fn build(&self, node: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        let link = self.links.get(&node.ino()).unwrap();

        self.pax_link_builder
            .build(EntryType::hard_link(), node, path, link)
    }
}

struct OCIWhiteoutBuilder {}

impl OCIWhiteoutBuilder {
    fn new() -> Self {
        OCIWhiteoutBuilder {}
    }
}

impl SectionBuilder for OCIWhiteoutBuilder {
    fn can_handle(&mut self, _: &dyn RafsInode, path: &Path) -> bool {
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(OCISPEC_WHITEOUT_PREFIX)
    }

    fn build(&self, inode: &dyn RafsInode, path: &Path) -> Result<Vec<TarSection>> {
        // In order to save access time and change time, gnu layout is required.
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::file());
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();
        header.set_size(0);

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(node.mode());

        // Rafs loses the access time and change time.
        // It's required by certain tools, such 7-zip.
        // Fill modify time as access time and change time.
        header.as_gnu_mut().unwrap().set_atime(node.mtime());
        header.as_gnu_mut().unwrap().set_ctime(node.mtime());

        let mut sections = Vec::with_capacity(2);
        if let Some(sect) = GNUUtil::set_path(&mut header, path)? {
            sections.push(sect);
        }

        header.set_cksum();

        let main_header = TarSection {
            header,
            data: Box::new(io::empty()),
        };
        sections.push(main_header);

        Ok(sections)
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
        header.set_mode(node.mode());

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.extend(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        header.set_cksum();

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
            self.compressor.as_ref().unwrap().clone(),
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
        header.set_mode(node.mode());
        header.set_size(node.size());

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.extend(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        header.set_cksum();

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
        header.set_mode(node.mode());
        header.set_size(node.size());

        let dev_id = self.cal_dev(inode.rdev() as u64);
        header.set_device_major(dev_id.0)?;
        header.set_device_minor(dev_id.1)?;

        let mut extensions = Vec::with_capacity(2);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.extend(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        header.set_cksum();

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

struct PAXExtensionSectionBuilder {}

impl PAXExtensionSectionBuilder {
    fn new() -> Self {
        PAXExtensionSectionBuilder {}
    }

    fn build(
        &self,
        header: &Header,
        extensions: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Option<TarSection>> {
        if extensions.len() == 0 {
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
            .map_err(|err| anyhow!("fail to set path for pax section, error {}", err))?;

        header.set_cksum();

        Ok(Some(TarSection {
            header,
            data: Box::new(Cursor::new(data)),
        }))
    }

    fn build_data(&self, mut extensions: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        extensions.sort_by(|(k1, _), (k2, _)| {
            let k1 = str::from_utf8(k1).unwrap();
            let k2 = str::from_utf8(k2).unwrap();
            k1.cmp(k2)
        });

        extensions
            .into_iter()
            .map(|(k, v)| self.build_pax_record(&k, &v))
            .flatten()
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
        header.set_mode(node.mode());

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = PAXUtil::set_path(&mut header, path)? {
            extensions.extend(extension);
        }
        if let Some(extension) = PAXUtil::set_link(&mut header, link)? {
            extensions.extend(extension);
        }
        if let Some(extension) = PAXUtil::get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        header.set_cksum();

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

struct GNUUtil {}

impl GNUUtil {
    fn set_path(header: &mut Header, path: &Path) -> Result<Option<TarSection>> {
        let path = Util::normalize_path(&path, header.entry_type().is_dir())
            .map_err(|err| anyhow!("fail to normalize path, error {}", err))?;

        let rs = match header.set_path(&path) {
            Ok(_) => return Ok(None),
            Err(err) => Err(anyhow!("fail to set path for header, error {}", err)),
        };

        let path = match Util::truncate_path(&path, header.as_old().name.len()) {
            Ok(path) => path,
            Err(_) => return rs,
        };

        header.set_path(&path).map_err(|err| {
            anyhow!(
                "fail to set header path again for {:?}, error {}",
                path,
                err
            )
        })?;

        Ok(Some(Self::build_long_section(
            EntryType::GNULongName,
            path.into_os_string().into_vec(),
        )))
    }

    fn build_long_section(entry_type: EntryType, mut data: Vec<u8>) -> TarSection {
        // gnu requires, especially for long-link section and long-name section
        let mut header = Header::new_gnu();

        data.push(0x00);
        header.set_size(data.len() as u64);
        let data = Cursor::new(data);

        let title = b"././@LongLink";
        header.as_gnu_mut().unwrap().name[..title.len()].clone_from_slice(&title[..]);

        header.set_entry_type(entry_type);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);

        header.set_cksum();

        TarSection {
            header,
            data: Box::new(data),
        }
    }
}

struct PAXUtil {}

impl PAXUtil {
    fn get_xattr_as_extensions(inode: &dyn RafsInode) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
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
            extensions.push((key, value));
        }

        Some(extensions)
    }

    fn set_link(header: &mut Header, path: &Path) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let path = Util::normalize_path(path, header.entry_type().is_dir())
            .map_err(|err| anyhow!("fail to normalize path, error {}", err))?;

        let max_len = header.as_old().linkname.len();
        if path.as_os_str().len() <= max_len {
            return header
                .set_link_name(&path)
                .map_err(|err| anyhow!("fail to set short path for pax header, error {}", err))
                .map(|_| None);
        }

        let extension = vec![(
            "linkpath".to_owned().into_bytes(),
            path.to_owned().into_os_string().into_vec(),
        )];

        let path = Util::truncate_path(&path, max_len)
            .map_err(|err| anyhow!("fail to truncate path for pax header, error {}", err))?;

        header.set_link_name(&path).map_err(|err| {
            anyhow!(
                "fail to set header path again for {:?}, error {}",
                path,
                err
            )
        })?;

        Ok(Some(extension))
    }

    fn set_path(header: &mut Header, path: &Path) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let path = Util::normalize_path(&path, header.entry_type().is_dir())
            .map_err(|err| anyhow!("fail to normalize path, error {}", err))?;

        let max_len = header.as_old().name.len();
        if path.as_os_str().len() <= max_len {
            return header
                .set_path(path)
                .map_err(|err| anyhow!("fail to set short path for pax header, error {}", err))
                .map(|_| None);
        }

        let extension = vec![(
            "path".to_owned().into_bytes(),
            path.to_owned().into_os_string().into_vec(),
        )];

        let path = Util::truncate_path(&path, max_len)
            .map_err(|err| anyhow!("fail to truncate path for pax header, error {}", err))?;

        header.set_path(&path).map_err(|err| {
            anyhow!(
                "fail to set header path again for {:?}, error {}",
                path,
                err
            )
        })?;

        Ok(Some(extension))
    }
}

struct Util {}

impl Util {
    fn normalize_path(path: &Path, is_dir: bool) -> Result<PathBuf> {
        fn has_trailing_slash(p: &Path) -> bool {
            p.as_os_str().as_bytes().last() == Some(&b'/')
        }

        // remove root
        let mut normalized = if path.has_root() {
            path.strip_prefix("/")
                .map_err(|err| anyhow!("fail to strip prefix /, error {}", err))?
                .to_path_buf()
        } else {
            path.to_path_buf()
        };

        // handle trailing slash
        if is_dir {
            normalized.push("");
        } else if has_trailing_slash(path) {
            normalized.set_file_name(normalized.file_name().unwrap().to_owned())
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
                .map_err(|err| anyhow!("fail to convert bytes to utf8 str, error: {}", err)),
        }?;

        Ok(PathBuf::from(path))
    }
}

struct OCITarBuilder {
    writer: Builder<File>,
    builders: Vec<Box<dyn SectionBuilder>>,
}

impl OCITarBuilder {
    fn new(meta: &RafsSuper, blob_dir: Option<&Path>, output_path: &Path) -> Result<Self> {
        let writer = Builder::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .read(false)
                .open(output_path)
                .map_err(|err| {
                    anyhow!(
                        "fail to open output file {:?}, error: {:?}",
                        output_path,
                        err
                    )
                })?,
        );

        let builders = Self::builders(meta, blob_dir)?;

        Ok(Self { builders, writer })
    }

    fn builders(meta: &RafsSuper, blob_dir: Option<&Path>) -> Result<Vec<Box<dyn SectionBuilder>>> {
        let pax_ext_builder = Rc::new(PAXExtensionSectionBuilder::new());
        let pax_link_builder = Rc::new(PAXLinkBuilder::new(pax_ext_builder.clone()));
        let pax_special_builder = Rc::new(PAXSpecialSectionBuilder::new(pax_ext_builder.clone()));

        let sock_builder = OCISocketBuilder::new();
        let link_builder = OCILinkBuilder::new(pax_link_builder.clone());
        let symlink_builder = OCISymlinkBuilder::new(pax_link_builder.clone());
        let whiteout_builder = OCIWhiteoutBuilder::new();
        let dir_builder = OCIDirBuilder::new(pax_ext_builder);
        let fifo_builder = OCIFifoBuilder::new(pax_special_builder.clone());
        let char_builder = OCICharBuilder::new(pax_special_builder.clone());
        let block_builder = OCIBlockBuilder::new(pax_special_builder);
        let reg_builder = Self::reg_builder(meta, blob_dir)?;

        let builders = vec![
            Box::new(sock_builder) as Box<dyn SectionBuilder>,
            Box::new(link_builder),
            Box::new(whiteout_builder),
            Box::new(dir_builder),
            Box::new(reg_builder),
            Box::new(symlink_builder),
            Box::new(fifo_builder),
            Box::new(char_builder),
            Box::new(block_builder),
        ];

        Ok(builders)
    }

    fn reg_builder(meta: &RafsSuper, blob_dir: Option<&Path>) -> Result<OCIRegBuilder> {
        let blob = meta.superblock.get_blob_infos().pop();
        let (reader, compressor) = match blob {
            None => (None, None),
            Some(ref blob) => {
                if blob_dir.is_none() {
                    bail!("miss blob dir")
                }

                let reader = Self::blob_reader(&blob_dir.unwrap().join(blob.blob_id()))?;
                let compressor = blob.compressor();

                (Some(reader), Some(compressor))
            }
        };

        let pax_ext_builder = Rc::new(PAXExtensionSectionBuilder::new());

        Ok(OCIRegBuilder::new(
            pax_ext_builder.clone(),
            reader,
            compressor,
        ))
    }

    fn blob_reader(blob_path: &Path) -> Result<Arc<dyn BlobReader>> {
        let config = LocalFsConfig {
            blob_file: blob_path.to_str().unwrap().to_owned(),
            readahead: false,
            readahead_sec: Default::default(),
            dir: Default::default(),
            alt_dirs: Default::default(),
        };
        let config = serde_json::to_value(config).map_err(|err| {
            anyhow!(
                "fail to create local backend config for {:?}, error: {:?}",
                blob_path,
                err
            )
        })?;

        let backend = LocalFs::new(config, Some("decompressor")).map_err(|err| {
            anyhow!(
                "fail to create local backend for {:?}, error: {:?}",
                blob_path,
                err
            )
        })?;

        let reader = backend
            .get_reader("")
            .map_err(|err| anyhow!("fail to get reader, error {:?}", err))?;

        Ok(reader)
    }
}

impl TarBuilder for OCITarBuilder {
    fn append(&mut self, inode: &dyn RafsInode, path: &Path) -> Result<()> {
        let mut is_known_type = true;

        for builder in &mut self.builders {
            if builder.can_handle(inode, path) {
                is_known_type = false;

                for sect in builder.build(inode, path)? {
                    self.writer.append(&sect.header, sect.data)?;
                }
            }
        }

        if is_known_type {
            bail!("node {:?} can not be decompressed", path)
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
        .map_err(|err| {
            error!("fail to decompress, error: {:?}", err);
            anyhow!("fail to decompress, error: {:?}", err)
        })?;

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
