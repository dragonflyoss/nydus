use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use clap::Args;

use lepton::build::blobchunk::BlobWriter;
use lepton::build::dir::{serialize_directory, DirChild};
use lepton::build::image::write_image;
use lepton::build::inode::{build_tree, inode_meta_size, serialize_inode, InodeData, InodeInfo};
use lepton::metadata::layout::MetadataLayout;
use lepton::metadata::*;

#[derive(Args)]
pub struct BuildArgs {
    /// Output image file path.
    image: PathBuf,

    /// Extra blob device to store chunked data.
    #[arg(long)]
    blobdev: PathBuf,

    /// Chunk size in bytes (must be a power of two, >= 4096).
    #[arg(long)]
    chunksize: u32,

    /// Source directory.
    source: PathBuf,
}

/// Run the build process to create an lepton image from the source directory.
pub fn run_build(args: BuildArgs) -> Result<()> {
    // Validate chunksize.
    if args.chunksize < EROFS_BLOCK_SIZE {
        bail!(
            "chunksize {} must be >= block size {}",
            args.chunksize,
            EROFS_BLOCK_SIZE
        );
    }
    if !args.chunksize.is_power_of_two() {
        bail!("chunksize {} must be a power of two", args.chunksize);
    }
    let chunkbits = args.chunksize.trailing_zeros();

    // Validate source is a directory.
    if !args.source.is_dir() {
        bail!("source {} is not a directory", args.source.display());
    }

    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();

    // Phase 1: Build inode tree and write chunk data to blobdev.
    eprintln!("Building filesystem tree from {}...", args.source.display());
    let mut blob_writer = BlobWriter::new(&args.blobdev, args.chunksize)?;
    let mut inodes = build_tree(&args.source, &mut blob_writer, args.chunksize)?;

    let total_inodes = inodes.len() as u64;
    eprintln!(
        "  {} inodes, {} blob blocks, {} bytes saved by dedup",
        total_inodes,
        blob_writer.total_blocks(),
        blob_writer.saved_by_dedup
    );

    // Phase 2: Layout metadata.
    eprintln!("Laying out metadata...");
    let mut layout = MetadataLayout::new();
    let blkszbits = EROFS_BLKSZBITS as u32;

    // Phase 2a: Allocate inode slots.
    for inode in &mut inodes {
        let meta_size = inode_meta_size(inode, chunkbits, blkszbits);
        let (offset, nid) = layout.alloc_inode(meta_size);
        inode.meta_offset = offset;
        inode.nid = nid;
    }

    // Set parent NIDs for directories.
    set_parent_nids(&mut inodes);

    // Phase 2b: Serialize and allocate directory data.
    layout.pad_to_block();

    let dir_infos: Vec<(usize, Vec<DirChild>, u64, u64)> = inodes
        .iter()
        .enumerate()
        .filter_map(|(idx, inode)| {
            if let InodeData::Directory {
                ref children,
                parent_nid,
                ..
            } = inode.data
            {
                let self_nid = inode.nid;
                let dir_children: Vec<DirChild> = children
                    .iter()
                    .map(|de| DirChild {
                        name: de.name.clone(),
                        nid: inodes[de.inode_idx].nid,
                        file_type: de.file_type,
                    })
                    .collect();
                Some((idx, dir_children, self_nid, parent_nid))
            } else {
                None
            }
        })
        .collect();

    for (idx, dir_children, self_nid, parent_nid) in dir_infos {
        let dir_data = serialize_directory(&dir_children, self_nid, parent_nid);
        let dir_data_len = dir_data.len();
        let (data_offset, startblk) = layout.alloc_dir_data(dir_data_len);
        layout.write_at(data_offset, &dir_data);

        if let InodeData::Directory {
            startblk: ref mut sb,
            dir_data_size: ref mut dds,
            ..
        } = inodes[idx].data
        {
            *sb = startblk;
            *dds = dir_data_len;
        }
        inodes[idx].size = dir_data_len as u64;
    }

    // Phase 2c: Serialize inodes into metadata buffer.
    for inode in &inodes {
        let inode_bytes = serialize_inode(inode, epoch, chunkbits);
        let offset = inode.meta_offset;
        layout.write_at(offset, &inode_bytes);
    }

    // Phase 3: Write image.
    eprintln!("Writing image to {}...", args.image.display());
    let root_nid = inodes[0].nid;
    assert!(root_nid <= u16::MAX as u64, "root NID exceeds 16-bit range");

    let uuid = uuid::Uuid::new_v4();
    let uuid_bytes: [u8; 16] = *uuid.as_bytes();

    let img_file = File::create(&args.image)
        .with_context(|| format!("failed to create image: {}", args.image.display()))?;
    let mut writer = BufWriter::new(img_file);

    write_image(
        &mut writer,
        &layout.buf,
        root_nid as u16,
        total_inodes,
        epoch,
        blob_writer.total_blocks(),
        &uuid_bytes,
    )?;

    eprintln!(
        "Done. Image: {} blocks, Blob: {} blocks",
        1 + layout.total_blocks(),
        blob_writer.total_blocks()
    );
    Ok(())
}

/// Set parent_nid for all directory inodes by traversing the tree.
fn set_parent_nids(inodes: &mut [InodeInfo]) {
    let root_nid = inodes[0].nid;
    if let InodeData::Directory {
        ref mut parent_nid, ..
    } = inodes[0].data
    {
        *parent_nid = root_nid;
    }

    let dir_infos: Vec<(u64, Vec<usize>)> = inodes
        .iter()
        .filter_map(|inode| {
            if let InodeData::Directory { ref children, .. } = inode.data {
                let child_dir_idxs: Vec<usize> = children
                    .iter()
                    .filter(|de| de.file_type == EROFS_FT_DIR)
                    .map(|de| de.inode_idx)
                    .collect();
                if child_dir_idxs.is_empty() {
                    None
                } else {
                    Some((inode.nid, child_dir_idxs))
                }
            } else {
                None
            }
        })
        .collect();

    for (parent_nid_val, child_idxs) in dir_infos {
        for child_idx in child_idxs {
            if let InodeData::Directory {
                ref mut parent_nid, ..
            } = inodes[child_idx].data
            {
                *parent_nid = parent_nid_val;
            }
        }
    }
}
