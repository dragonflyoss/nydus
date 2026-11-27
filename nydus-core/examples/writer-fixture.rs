use std::path::{Path, PathBuf};

use nydus_config::Config;
use nydus_core::{IncrementalWriter, IncrementalWriterOptions, NydusCore};

/// Writes an incremental child of a parent holding `changed` and `unchanged`,
/// for the cross-language e2e publisher.
///
/// ```text
/// writer-fixture --bootstrap PATH --blob-dir DIR --output-dir DIR
/// ```
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the flags.
    let mut bootstrap = None;
    let mut blob_dir = None;
    let mut output_dir = None;
    let mut use_cache_layout = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--cache-layout" {
            use_cache_layout = true;
            continue;
        }
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
    let output_dir = output_dir.ok_or("--output-dir is required")?;

    // Open the parent, quoting paths as YAML strings.
    std::fs::create_dir_all(&output_dir)?;
    let options = IncrementalWriterOptions::new(output_dir.clone());
    let has_parent = bootstrap.is_some();
    let mut writer = if let Some(bootstrap) = bootstrap {
        let blob_dir = blob_dir.ok_or("--blob-dir is required with --bootstrap")?;
        let config = serde_yaml::from_str::<Config>(&format!(
        "backend:\n  type: local\n  config:\n    dir: {:?}\nstorage:\n  dir: {:?}\nprefetch:\n  scope: none\n",
        blob_dir.to_str().ok_or("blob directory must be UTF-8")?,
        output_dir.join("cache").to_str().ok_or("output directory must be UTF-8")?,
    ))?;
        let core = NydusCore::new(&bootstrap, config, None)?;
        core.writer(options)?
    } else if use_cache_layout {
        let mut writer = IncrementalWriter::create(options)?;
        writer.replace_file(Path::new("unchanged"), b"capture unchanged\n".to_vec())?;
        writer
    } else {
        return Err("--bootstrap is required unless --cache-layout is used".into());
    };

    // Write the child: keep `unchanged`, replace `changed`, create `created`.
    writer.open_file(Path::new("unchanged"))?;
    let changed = if has_parent {
        b"child changed\n".as_slice()
    } else {
        b"capture changed\n".as_slice()
    };
    writer.replace_file(Path::new("changed"), changed.to_vec())?;
    let data = b"child created\n";
    writer.replace_file(Path::new("created"), data.to_vec())?;
    if use_cache_layout {
        writer.commit_cache_to_dir()?;
    } else {
        writer.commit()?;
    }
    Ok(())
}
