use std::{
    fs::{File, OpenOptions},
    io::Read,
    iter::from_fn,
    path::{Path, PathBuf},
    rc::Rc,
    str,
    sync::Arc,
};

use anyhow::{Context, Result};
use nydus_api::http::LocalFsConfig;
use nydus_rafs::{
    metadata::{RafsInode, RafsMode, RafsSuper},
    RafsIoReader,
};
use storage::{
    backend::{localfs::LocalFs, BlobBackend, BlobReader},
    device::BlobInfo,
};
use tar::{Builder, Header};

use self::pax::{
    OCIBlockBuilder, OCICharBuilder, OCIDirBuilder, OCIFifoBuilder, OCILinkBuilder, OCIRegBuilder,
    OCISocketBuilder, OCISymlinkBuilder, PAXExtensionSectionBuilder, PAXLinkBuilder,
    PAXSpecialSectionBuilder,
};

mod pax;

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
        for builder in &mut self.builders {
            // Useless one, just go !!!!!
            if !builder.can_handle(inode, path) {
                continue;
            }

            for sect in builder.build(inode, path)? {
                self.writer.append(&sect.header, sect.data)?;
            }

            return Ok(());
        }

        bail!("node {:?} can not be unpacked", path)
    }
}
