extern crate tar;

use std::{
    borrow::Borrow,
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Cursor, Error, ErrorKind, Read},
    iter::from_fn,
    os::unix::prelude::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    str,
    sync::Arc,
    vec::IntoIter,
};

use anyhow::{Context, Result};
use nydus_rafs::{
    metadata::{layout::RAFS_ROOT_INODE, RafsInode, RafsMode, RafsSuper},
    RafsIoReader,
};
use nydus_utils::compress::{self, Algorithm};
use storage::{
    backend::{localfs::LocalFs, BlobBackend, BlobReader, LocalFsConfig},
    device::{BlobChunkInfo, BlobInfo},
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
pub struct DefaultDecompressor {
    bootstrap_path: Box<Path>,
    blob_path: Box<Path>,
    output_path: String,
}

impl DefaultDecompressor {
    pub fn new(bootstrap: &str, blob: &str, output: &str) -> Result<Self> {
        let bootstrap_path = PathBuf::from(bootstrap).canonicalize()?.into_boxed_path();
        let blob_path = PathBuf::from(blob).canonicalize()?.into_boxed_path();

        let output_path = output.to_owned();

        Ok(DefaultDecompressor {
            bootstrap_path,
            blob_path,
            output_path,
        })
    }

    fn load_meta(&self) -> Result<RafsSuper> {
        let bootstrap = OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.bootstrap_path.as_ref())
            .map_err(|err| {
                error!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap_path, err
                );
                anyhow!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap_path,
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
                    self.bootstrap_path, err
                );
                anyhow!(
                    "fail to load bootstrap {:?}, error: {}",
                    self.bootstrap_path,
                    err
                )
            })?;

        Ok(rs)
    }

    /// A lazy iterator of RafsInode in DFS.
    fn iterator<'a>(
        &'a self,
        rs: &'a RafsSuper,
    ) -> Box<impl Iterator<Item = (Arc<dyn RafsInode>, Box<Path>)> + 'a> {
        let mut cursor_stack = Vec::with_capacity(32);
        cursor_stack.push(self.cursor_of_root(rs));

        let dfs_cursor = move || {
            while !cursor_stack.is_empty() {
                let mut cursor = cursor_stack.pop().unwrap();
                let (node, path) = if let Some(iterm) = cursor.next() {
                    cursor_stack.push(cursor);
                    iterm
                } else {
                    continue;
                };

                if node.is_dir() {
                    cursor_stack.push(self.cursor_of_children(node.clone(), path.as_ref()))
                }

                return Some((node, path));
            }

            None
        };

        Box::new(from_fn(dfs_cursor))
    }

    fn cursor_of_children(
        &self,
        node: Arc<dyn RafsInode>,
        path: &Path,
    ) -> Box<dyn Iterator<Item = (Arc<dyn RafsInode>, Box<Path>)>> {
        let path = path.to_path_buf();
        let mut cursor = 0..node.get_child_count();

        let visitor = from_fn(move || {
            if cursor.is_empty() {
                return None;
            }

            let child = node.get_child_by_index(cursor.next().unwrap()).unwrap();
            let child_path = path.join(child.name()).into_boxed_path();

            Some((child, child_path))
        });

        Box::new(visitor)
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

impl Decompressor for DefaultDecompressor {
    fn decompress(&self) -> Result<()> {
        info!(
            "default decompressor, bootstrap file: {:?}, blob file: {:?}, output file: {}",
            self.bootstrap_path, self.blob_path, self.output_path
        );

        let meta = self.load_meta()?;

        let mut builder = Box::new(DefaultTarBuilder::new(
            &meta,
            self.blob_path.as_ref(),
            self.output_path.as_ref(),
        )?) as Box<dyn TarBuilder>;

        for (node, path) in self.iterator(&meta) {
            // Not write root node to tar.
            if node.name() == OsStr::from_bytes(ROOT_PATH_NAME) {
                continue;
            }

            builder
                .append(node.as_ref(), path.as_ref())
                .with_context(|| "fail to append inode to tar")?;
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
    presections: Vec<TarSection>,
}

struct DefaultTarBuilder {
    blob: Option<Arc<BlobInfo>>,
    reader: Option<Arc<dyn BlobReader>>,
    writer: Builder<File>,
    links: HashMap<u64, Box<Path>>,
}

impl DefaultTarBuilder {
    fn new(meta: &RafsSuper, blob_path: &Path, output_path: &Path) -> Result<Self> {
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

        let blob = meta.superblock.get_blob_infos().pop();
        let reader = if blob.is_some() {
            Some(Self::chunk_reader(
                &blob_path.join(blob.as_ref().unwrap().blob_id()),
            )?)
        } else {
            None
        };

        Ok(Self {
            blob,
            reader,
            writer,
            links: HashMap::new(),
        })
    }

    fn chunk_reader(blob_path: &Path) -> Result<Arc<dyn BlobReader>> {
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

        let reader = backend.get_reader("").map_err(|err| {
            anyhow!(
                "fail to get chunk reader for {:?}, error: {:?}",
                blob_path,
                err
            )
        })?;

        Ok(reader)
    }

    fn build_whiteout_section(&self, inode: &dyn RafsInode, path: &Path) -> Result<TarSection> {
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

        let mut requirements = Vec::with_capacity(1);
        if let Some(requirement) = self.set_path_for_gnu_header(&mut header, path)? {
            requirements.push(requirement);
        }

        header.set_cksum();

        Ok(TarSection {
            header,
            data: Box::new(io::empty()),
            presections: Vec::new(),
        })
    }

    fn build_dir_section(&self, inode: &dyn RafsInode, path: &Path) -> Result<TarSection> {
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

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = self.set_path_for_pax_header(&mut header, path)? {
            extensions.extend(extension);
        }

        header.set_cksum();

        if let Some(extension) = self.get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        let mut requirements = Vec::with_capacity(1);
        if let Some(xattr) =
            self.build_extension_section(header.path().unwrap().borrow(), extensions)?
        {
            requirements.push(xattr);
        }

        Ok(TarSection {
            header,
            data: Box::new(io::empty()),
            presections: requirements,
        })
    }

    fn build_reg_section(&self, inode: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        if self.blob.is_none() || self.reader.is_none() {
            bail!("miss blob meta or chunk reader for building regular header")
        }

        let chunks: Vec<Arc<dyn BlobChunkInfo>> = (0..inode.get_chunk_count())
            .map(|i| inode.get_chunk_info(i).unwrap())
            .collect();
        let data = ChunkReader::new(
            self.blob.as_ref().unwrap().compressor(),
            self.reader.as_ref().unwrap().clone(),
            chunks,
        );

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

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = self.set_path_for_pax_header(&mut header, path)? {
            extensions.extend(extension);
        }

        header.set_cksum();

        if let Some(extension) = self.get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        let mut requirements = Vec::with_capacity(1);
        if let Some(xattr) =
            self.build_extension_section(header.path().unwrap().borrow(), extensions)?
        {
            requirements.push(xattr);
        }

        Ok(TarSection {
            header,
            data: Box::new(data),
            presections: requirements,
        })
    }

    fn build_symlink_section(&self, node: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        let link = node.get_symlink().unwrap();

        self._build_link_section(EntryType::symlink(), node, path, &PathBuf::from(link))
    }

    fn build_link_section(&self, node: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        let link = self.links.get(&node.ino()).unwrap();

        self._build_link_section(EntryType::hard_link(), node, path, link)
    }

    fn build_fifo_section(&self, node: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        self.build_special_file_section(EntryType::Fifo, node, path)
    }

    fn build_char_section(&self, node: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        self.build_special_file_section(EntryType::character_special(), node, path)
    }

    fn build_block_section(&self, node: &dyn RafsInode, path: &Path) -> Result<TarSection> {
        self.build_special_file_section(EntryType::block_special(), node, path)
    }

    fn _build_link_section(
        &self,
        entry_type: EntryType,
        inode: &dyn RafsInode,
        path: &Path,
        link: &Path,
    ) -> Result<TarSection> {
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
        if let Some(extension) = self.set_path_for_pax_header(&mut header, path)? {
            extensions.extend(extension);
        }
        if let Some(extension) = self.set_link_for_pax_header(&mut header, link)? {
            extensions.extend(extension);
        }

        header.set_cksum();

        if let Some(extension) = self.get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        let mut requirements = Vec::with_capacity(1);
        if let Some(xattr) =
            self.build_extension_section(header.path().unwrap().borrow(), extensions)?
        {
            requirements.push(xattr);
        }

        Ok(TarSection {
            header,
            data: Box::new(io::empty()),
            presections: requirements,
        })
    }

    fn build_special_file_section(
        &self,
        entry_type: EntryType,
        inode: &dyn RafsInode,
        path: &Path,
    ) -> Result<TarSection> {
        let mut header = Header::new_ustar();
        header.set_entry_type(entry_type);

        let node = InodeWrapper::from_inode_info(inode);
        header.set_mtime(node.mtime());
        header.set_uid(node.uid() as u64);
        header.set_gid(node.gid() as u64);
        header.set_mode(node.mode());
        header.set_size(node.size());

        let dev_id = inode.rdev() as u64;
        let dev_major = ((dev_id >> 32) & 0xffff_f000) | ((dev_id >> 8) & 0x0000_0fff);
        header.set_device_major(dev_major as u32)?;

        let dev_minor = ((dev_id >> 12) & 0xffff_ff00) | ((dev_id) & 0x0000_00ff);
        header.set_device_minor(dev_minor as u32)?;

        let mut extensions = Vec::with_capacity(3);
        if let Some(extension) = self.set_path_for_pax_header(&mut header, path)? {
            extensions.extend(extension);
        }

        header.set_cksum();

        if let Some(extension) = self.get_xattr_as_extensions(inode) {
            extensions.extend(extension);
        }

        let mut requirements = Vec::with_capacity(1);
        if let Some(xattr) =
            self.build_extension_section(header.path().unwrap().borrow(), extensions)?
        {
            requirements.push(xattr);
        }

        Ok(TarSection {
            header,
            data: Box::new(io::empty()),
            presections: requirements,
        })
    }

    fn build_extension_section(
        &self,
        path: &Path,
        mut extensions: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Option<TarSection>> {
        if extensions.len() == 0 {
            return Ok(None);
        }

        let mut header = Header::new_ustar();
        header.set_entry_type(EntryType::XHeader);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);

        extensions.sort_by(|(k1, _), (k2, _)| {
            let k1 = str::from_utf8(k1).unwrap();
            let k2 = str::from_utf8(k2).unwrap();

            k1.cmp(k2)
        });
        let data: Vec<u8> = extensions
            .into_iter()
            .map(|(k, v)| self.build_pax_record(&k, &v))
            .flatten()
            .collect();
        header.set_size(data.len() as u64);

        let mut path = self.build_pax_name(path);
        let max_len = header.as_old().name.len();
        if path.as_os_str().len() > max_len {
            path = self.truncate_path(&path, max_len)?;
        }
        header
            .set_path(&path)
            .map_err(|err| anyhow!("fail to set path for pax section, error {}", err))?;

        header.set_cksum();

        Ok(Some(TarSection {
            header,
            data: Box::new(Cursor::new(data)),
            presections: Vec::new(),
        }))
    }

    fn build_long_section(&self, entry_type: EntryType, mut data: Vec<u8>) -> TarSection {
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
            presections: Vec::new(),
        }
    }

    fn get_xattr_as_extensions(&self, inode: &dyn RafsInode) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
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

    fn build_pax_name(&self, path: &Path) -> PathBuf {
        let mut path = path.to_path_buf();
        let filename = path.file_name().unwrap().to_owned();
        path.set_file_name("PaxHeaders.0");
        path.join(filename)
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

    fn set_path_for_pax_header(
        &self,
        header: &mut Header,
        path: &Path,
    ) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let path = self
            .normalize_path(&path, header.entry_type().is_dir())
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

        let path = self
            .truncate_path(&path, max_len)
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

    fn set_path_for_gnu_header(
        &self,
        header: &mut Header,
        path: &Path,
    ) -> Result<Option<TarSection>> {
        let path = self
            .normalize_path(&path, header.entry_type().is_dir())
            .map_err(|err| anyhow!("fail to normalize path, error {}", err))?;

        let rs = match header.set_path(&path) {
            Ok(_) => return Ok(None),
            Err(err) => Err(anyhow!("fail to set path for header, error {}", err)),
        };

        let path = match self.truncate_path(&path, header.as_old().name.len()) {
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

        Ok(Some(self.build_long_section(
            EntryType::GNULongName,
            path.into_os_string().into_vec(),
        )))
    }

    // path is required longer than max_len
    fn truncate_path(&self, path: &Path, max_len: usize) -> Result<PathBuf> {
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

    /// If link size is too long, a long-link-header is returned as precondition of input
    /// header.
    fn set_link_for_pax_header(
        &self,
        header: &mut Header,
        path: &Path,
    ) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let path = self
            .normalize_path(path, header.entry_type().is_dir())
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

        let path = self
            .truncate_path(&path, max_len)
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

    fn normalize_path(&self, path: &Path, is_dir: bool) -> Result<PathBuf> {
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

    fn is_link_section(&mut self, node: &dyn RafsInode, path: &Path) -> bool {
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

    fn is_symlink_section(&self, node: &dyn RafsInode) -> bool {
        node.is_symlink()
    }

    fn is_socket_section(&self, node: &dyn RafsInode) -> bool {
        InodeWrapper::from_inode_info(node).is_sock()
    }

    fn is_dir_section(&self, node: &dyn RafsInode) -> bool {
        node.is_dir()
    }

    fn is_reg_section(&self, node: &dyn RafsInode) -> bool {
        node.is_reg()
    }

    fn is_fifo_section(&self, node: &dyn RafsInode) -> bool {
        InodeWrapper::from_inode_info(node).is_fifo()
    }

    fn is_char_section(&self, node: &dyn RafsInode) -> bool {
        InodeWrapper::from_inode_info(node).is_chrdev()
    }

    fn is_block_section(&self, node: &dyn RafsInode) -> bool {
        InodeWrapper::from_inode_info(node).is_blkdev()
    }

    fn is_white_out_section(&self, path: &Path) -> bool {
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(OCISPEC_WHITEOUT_PREFIX)
    }
}

impl TarBuilder for DefaultTarBuilder {
    fn append(&mut self, inode: &dyn RafsInode, path: &Path) -> Result<()> {
        let tar_sect = match inode {
            node if self.is_socket_section(node) => return Ok(()),

            node if self.is_link_section(node, path) => self.build_link_section(node, path)?,

            node if self.is_white_out_section(path) => self.build_whiteout_section(node, path)?,

            node if self.is_dir_section(node) => self.build_dir_section(node, path)?,

            node if self.is_reg_section(node) => self.build_reg_section(node, path)?,

            node if self.is_symlink_section(node) => self.build_symlink_section(node, path)?,

            node if self.is_fifo_section(node) => self.build_fifo_section(node, path)?,

            node if self.is_char_section(node) => self.build_char_section(node, path)?,

            node if self.is_block_section(node) => self.build_block_section(node, path)?,

            _ => bail!("unknow inde type"),
        };

        for sect in tar_sect.presections {
            self.writer
                .append(&sect.header, sect.data)
                .map_err(|err| anyhow!("fail to append inode {:?}, error: {}", path, err))?;
        }

        self.writer
            .append(&tar_sect.header, tar_sect.data)
            .map_err(|err| anyhow!("fail to append inode {:?}, error: {}", path, err))?;

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
