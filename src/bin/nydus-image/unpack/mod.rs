// Copyright 2022 Ant Group. All rights reserved.
// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::fs::{create_dir_all, remove_file, File, OpenOptions};
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
use tar::{Archive, Builder, Header};

use self::pax::{
    OCIBlockBuilder, OCICharBuilder, OCIDirBuilder, OCIFifoBuilder, OCILinkBuilder, OCIRegBuilder,
    OCISocketBuilder, OCISymlinkBuilder, PAXExtensionSectionBuilder, PAXLinkBuilder,
    PAXSpecialSectionBuilder,
};

mod pax;

pub trait Unpacker {
    fn unpack(&self, config: Arc<ConfigV2>) -> Result<()>;
}

///  A unpacker with the ability to convert bootstrap file and blob file to tar or dir.
pub struct OCIUnpacker {
    bootstrap: PathBuf,
    blob_backend: Option<Arc<dyn BlobBackend + Send + Sync>>,
    output: PathBuf,
    untar: bool,

    builder_factory: OCITarBuilderFactory,
}

impl OCIUnpacker {
    pub fn new(
        bootstrap: &Path,
        blob_backend: Option<Arc<dyn BlobBackend + Send + Sync>>,
        output: &str,
        untar: bool,
    ) -> Result<Self> {
        let bootstrap = bootstrap.to_path_buf();
        let output = PathBuf::from(output);

        let builder_factory = OCITarBuilderFactory::new();

        Ok(OCIUnpacker {
            builder_factory,
            bootstrap,
            blob_backend,
            output,
            untar,
        })
    }

    fn load_rafs(&self, config: Arc<ConfigV2>) -> Result<RafsSuper> {
        let (rs, _) = RafsSuper::load_from_file(self.bootstrap.as_path(), config, false)?;
        Ok(rs)
    }

    fn get_unpack_path(&self) -> Result<PathBuf> {
        // If output ends with path separator, then it is a dir.
        let is_dir = self
            .output
            .to_string_lossy()
            .ends_with(std::path::MAIN_SEPARATOR);

        // Unpack the tar file to a subdirectory
        if is_dir || self.untar {
            if !self.output.exists() {
                create_dir_all(&self.output)?;
            }
            let tar_path = self
                .output
                .join(self.bootstrap.file_stem().unwrap_or_default())
                .with_extension("tar");

            return Ok(tar_path);
        }

        // Unpack the tar file to the specified location
        Ok(self.output.clone())
    }
}

impl Unpacker for OCIUnpacker {
    fn unpack(&self, config: Arc<ConfigV2>) -> Result<()> {
        debug!(
            "oci unpacker, bootstrap file: {:?}, output path: {:?}",
            self.bootstrap, self.output
        );

        let rafs = self.load_rafs(config)?;

        let tar_path = self.get_unpack_path()?;
        let mut builder = self
            .builder_factory
            .create(&rafs, &self.blob_backend, &tar_path)?;

        for (node, path) in RafsIterator::new(&rafs) {
            builder.append(node, &path)?;
        }
        info!("successfully unpack image to: {}", tar_path.display());

        // untar this tar file to self.output dir
        if self.untar {
            let file = File::open(&tar_path)?;
            let mut tar = Archive::new(file);
            tar.unpack(&self.output)?;
            remove_file(&tar_path)?;

            info!(
                "successfully untar {} to: {}",
                tar_path.display(),
                self.output.display()
            );
        }

        Ok(())
    }
}

trait TarBuilder {
    fn append(&mut self, node: Arc<dyn RafsInodeExt>, path: &Path) -> Result<()>;
}

struct TarSection {
    header: Header,
    data: Box<dyn Read>,
}

trait SectionBuilder {
    fn can_handle(&mut self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> bool;
    fn build(&self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<Vec<TarSection>>;
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

        let builders = self.create_builders(meta, blob_backend)?;

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
        meta: &RafsSuper,
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
        let blobs = meta.superblock.get_blob_infos();
        let reg_builder = self.create_reg_builder(blobs, blob_backend)?;

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
        blobs: Vec<Arc<BlobInfo>>,
        blob_backend: &Option<Arc<dyn BlobBackend + Send + Sync>>,
    ) -> Result<OCIRegBuilder> {
        let mut readers = HashMap::new();
        let mut compressors = HashMap::new();
        for blob in blobs {
            let blob_backend = blob_backend
                .as_deref()
                .with_context(|| "both blob path or blob backend config are not specified")?;
            let reader = blob_backend
                .get_reader(blob.blob_id().as_str())
                .map_err(|err| anyhow!("fail to get reader, error {:?}", err))?;

            let compressor = blob.compressor();
            readers.insert(blob.blob_index(), reader);
            compressors.insert(blob.blob_index(), compressor);
        }

        Ok(OCIRegBuilder::new(
            Rc::new(PAXExtensionSectionBuilder::new()),
            readers,
            compressors,
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
    fn append(&mut self, inode: Arc<dyn RafsInodeExt>, path: &Path) -> Result<()> {
        for builder in &mut self.builders {
            // Useless one, just go !!!!!
            if !builder.can_handle(inode.clone(), path) {
                continue;
            }

            for sect in builder.build(inode.clone(), path)? {
                self.writer.append(&sect.header, sect.data)?;
            }

            return Ok(());
        }

        bail!("node {:?} can not be unpacked", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_unpack_path() {
        // test data: (bootstrap, output, untar, expected_tar_path)
        let test_cases = [
            ("./test", "target.tar", false, "target.tar"),
            ("test/test", "target", false, "target"),
            ("test/test", "target/", false, "target/test.tar"),
            ("/run/test.meta", "target/", false, "target/test.tar"),
            ("/run/test.meta", "/run/", false, "/run/test.tar"),
            ("./test", "target.tar", true, "target.tar/test.tar"),
            ("test/test", "target", true, "target/test.tar"),
            ("test/test", "target/", true, "target/test.tar"),
        ];

        for (bootstrap, output, untar, expected_tar_path) in test_cases {
            let unpacker = OCIUnpacker::new(Path::new(bootstrap), None, output, untar).unwrap();
            let tar_path = unpacker.get_unpack_path().unwrap();
            assert_eq!(
                tar_path,
                PathBuf::from(expected_tar_path),
                "tar_path not equal to expected_tar_path"
            );
        }
    }
}
