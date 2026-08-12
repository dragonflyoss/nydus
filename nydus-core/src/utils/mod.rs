pub mod align;
pub mod digest;
pub mod io;
pub mod le;
#[cfg(target_os = "linux")]
pub mod mount;

/// One mebibyte (1 MiB) in bytes.
pub const MIB: u32 = 1 << 20;

pub use self::align::{align_up, round_up};
pub use self::digest::{
    hex_string, parse_sha256_hex, sha256_bytes, sha256_file, sha256_file_range, SHA256_DIGEST_SIZE,
};
pub use self::io::{pread_exact, write_zero_padding};
#[cfg(target_os = "linux")]
pub use self::mount::{path_cstring, unmount};
