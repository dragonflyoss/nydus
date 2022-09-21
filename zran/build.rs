use anyhow::Result;

fn main() -> Result<()> {
    // Skip installing dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    cc::Build::new()
        .file("libzran/indexer.c")
        .include("libzran/")
        .compile("zran");
    println!("cargo:rerun-if-changed=libzran/indexer.c");
    println!("cargo:rustc-link-lib=static=zran");
    println!("cargo:rustc-link-lib=z");
    Ok(())
}
