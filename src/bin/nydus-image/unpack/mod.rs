// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::{
    metadata::{RafsInodeExt, RafsSuper},
    RafsIterator,
};
use nydus_storage::backend::BlobBackend;
use nydus_storage::device::BlobInfo;
use tar::{Builder, Header};

use self::pax::{
    OCIBlockBuilder, OCICharBuilder, OCIDirBuilder, OCIFifoBuilder, OCILinkBuilder, OCIRegBuilder,
    OCISocketBuilder, OCISymlinkBuilder, PAXExtensionSectionBuilder, PAXLinkBuilder,
    PAXSpecialSectionBuilder,
};

mod pax;

pub trait Unpacker {
    fn unpack(&self, config: Arc<ConfigV2>) -> Result<()>;
}

///  A unpacker with the ability to convert bootstrap file and blob file to tar
pub struct OCIUnpacker {
    bootstrap: PathBuf,
    blob_backend: Option<Arc<dyn BlobBackend + Send + Sync>>,
    output: PathBuf,

    builder_factory: OCITarBuilderFactory,
}

impl OCIUnpacker {
    pub fn new(
        bootstrap: &Path,
        blob_backend: Option<Arc<dyn BlobBackend + Send + Sync>>,
        output: &str,
    ) -> Result<Self> {
        let bootstrap = bootstrap.to_path_buf();
        let output = PathBuf::from(output);

        let builder_factory = OCITarBuilderFactory::new();

        Ok(OCIUnpacker {
            builder_factory,
            bootstrap,
            blob_backend,
            output,
        })
    }

    fn load_rafs(&self, config: Arc<ConfigV2>) -> Result<RafsSuper> {
        let (rs, _) = RafsSuper::load_from_file(
            self.bootstrap.as_path(),
            config.clone(),
            config.is_chunk_validation_enabled(),
            false,
        )?;
        Ok(rs)
    }
}

impl Unpacker for OCIUnpacker {
    fn unpack(&self, config: Arc<ConfigV2>) -> Result<()> {
        debug!(
            "oci unpacker, bootstrap file: {:?}, output file: {:?}",
            self.bootstrap, self.output
        );

        let rafs = self.load_rafs(config)?;

        let mut builder = self
            .builder_factory
            .create(&rafs, &self.blob_backend, &self.output)?;

        for (node, path) in RafsIterator::new(&rafs) {
            builder.append(&*node, &path)?;
        }

        Ok(())
    }
}

trait TarBuilder {
    fn append(&mut self, node: &dyn RafsInodeExt, path: &Path) -> Result<()>;
}

struct TarSection {
    header: Header,
    data: Box<dyn Read>,
}

trait SectionBuilder {
    fn can_handle(&mut self, inode: &dyn RafsInodeExt, path: &Path) -> bool;
    fn build(&self, inode: &dyn RafsInodeExt, path: &Path) -> Result<Vec<TarSection>>;
}

struct OCITarBuilderFactory {}

impl OCITarBuilderFactory {
    fn new() -> Self {
        OCITarBuilderFactory {}
    }

    fn create(
        &self,
        meta: &RafsSuper,
        blob_backend: &Option<Arc<dyn BlobBackend + Send + Sync>>,
        output_path: &Path,
    ) -> Result<Box<dyn TarBuilder>> {
        let writer = self.create_writer(output_path)?;

        let blob = meta.superblock.get_blob_infos().pop();
        let builders = self.create_builders(blob, blob_backend)?;

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
        blob_backend: &Option<Arc<dyn BlobBackend + Send + Sync>>,
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
        let reg_builder = self.create_reg_builder(blob, blob_backend)?;

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
        blob_backend: &Option<Arc<dyn BlobBackend + Send + Sync>>,
    ) -> Result<OCIRegBuilder> {
        let (reader, compressor) = match blob {
            None => (None, None),
            Some(ref blob) => {
                let blob_backend = blob_backend
                    .as_deref()
                    .with_context(|| "both blob path or blob backend config are not specified")?;
                let reader = blob_backend
                    .get_reader("unpacker")
                    .map_err(|err| anyhow!("fail to get reader, error {:?}", err))?;

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
    fn append(&mut self, inode: &dyn RafsInodeExt, path: &Path) -> Result<()> {
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
