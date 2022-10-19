# nydus-app

The `nydus-app` crate is a collection of utilities to help creating applications for [`Nydus Image Service`](https://github.com/dragonflyoss/image-service) project, which provides:
- `struct BuildTimeInfo`: application build and version information.
- `fn dump_program_info()`: dump program build and version information.
- `fn setup_logging()`: setup logging infrastructure for application.

## Support

**Platforms**:
- x86_64
- aarch64

**Operating Systems**:
- Linux

## Usage

Add `nydus-app` as a dependency in `Cargo.toml`

```toml
[dependencies]
nydus-app = "*"
```

Then add `extern crate nydus-app;` to your crate root if needed.

## Examples

- Setup application infrastructure.

```rust
#[macro_use(crate_authors, crate_version)]
extern crate clap;

use clap::App;
use std::io::Result;
use nydus_app::{BuildTimeInfo, setup_logging};

fn main() -> Result<()> {
    let level = cmd.value_of("log-level").unwrap().parse().unwrap();
    let (bti_string, build_info) = BuildTimeInfo::dump();
    let _cmd = App::new("")
        .version(bti_string.as_str())
        .author(crate_authors!())
        .get_matches();

    setup_logging(None, level)?;
    print!("{}", build_info);
    
    Ok(())
}
```

## License

This code is licensed under [Apache-2.0](LICENSE).
