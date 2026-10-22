//! Generate a real incremental child for the cross-language E2E publisher.
//! Usage: writer-fixture --bootstrap PATH --blob-dir DIR --output-dir DIR
//! The parent must contain `changed` and `unchanged`; outputs use the writer's
//! standard `image.boot`, digest-named upper blob, and metadata sidecar.

use std::path::{Path, PathBuf};

use nydus_config::Config;
use nydus_core::{CreateFileOptions, IncrementalWriterOptions, NydusCore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bootstrap = None;
    let mut blob_dir = None;
    let mut output_dir = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let slot = match flag.to_str() {
            Some("--bootstrap") => &mut bootstrap,
            Some("--blob-dir") => &mut blob_dir,
            Some("--output-dir") => &mut output_dir,
            _ => return Err(format!("unknown argument: {flag:?}").into()),
        };
        if slot.is_some() {
            return Err(format!("duplicate argument: {flag:?}").into());
        }
        *slot = Some(PathBuf::from(args.next().ok_or("missing argument value")?));
    }
    let bootstrap = bootstrap.ok_or("--bootstrap is required")?;
    let blob_dir = blob_dir.ok_or("--blob-dir is required")?;
    let output_dir = output_dir.ok_or("--output-dir is required")?;
    std::fs::create_dir_all(&output_dir)?;
    // Quote paths as YAML strings, including spaces and embedded punctuation.
    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {:?}\nstorage:\n  dir: {:?}\nprefetch:\n  scope: none\n",
        blob_dir.to_str().ok_or("blob directory must be UTF-8")?,
        output_dir.join("cache").to_str().ok_or("output directory must be UTF-8")?,
    ))?;
    let core = NydusCore::new(&bootstrap, config, None)?;
    let mut writer = core.writer(IncrementalWriterOptions::new(output_dir))?;
    writer.open_file(Path::new("unchanged"))?;
    writer.replace_file(Path::new("changed"), b"child changed\n".to_vec())?;
    let data = b"child created\n";
    writer
        .create_file(
            Path::new("created"),
            data.len() as u64,
            CreateFileOptions::default(),
        )?
        .write_at(0, data)?;
    writer.commit()?;
    Ok(())
}
