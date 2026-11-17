use std::path::Path;

/// Reads the top mount's device and filesystem type without accessing a potentially stalled filesystem.
pub(crate) fn mount_entry_of(target: &Path) -> std::io::Result<Option<(String, String)>> {
    Ok(mount_entry_from(
        &std::fs::read_to_string("/proc/self/mountinfo")?,
        target,
    ))
}

/// Decodes mountinfo octal escapes as bytes to preserve UTF-8 paths.
fn unescape_mountinfo(field: &str) -> String {
    let mut out = Vec::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let octal: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&octal, 8) {
            Ok(byte) if octal.len() == 3 => {
                out.push(byte);
                for _ in 0..3 {
                    chars.next();
                }
            }
            _ => out.push(b'\\'),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns the device and filesystem type of the top mount at `target` in a mountinfo snapshot.
fn mount_entry_from(mountinfo: &str, target: &Path) -> Option<(String, String)> {
    let target = target.as_os_str().to_string_lossy();

    // Later entries shadow earlier ones when mounts are stacked.
    mountinfo.lines().rev().find_map(|line| {
        let (head, tail) = line.split_once(" - ")?;
        let mut fields = head.split_whitespace();
        let device = fields.nth(2)?;
        let point = fields.nth(1)?;
        if unescape_mountinfo(point) != target {
            return None;
        }
        Some((device.into(), tail.split_whitespace().next()?.into()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_mountinfo_decodes_octal_escapes_as_bytes() {
        let test_cases = vec![
            (r"/mnt/a\040b", "/mnt/a b"),
            ("/mnt/plain", "/mnt/plain"),
            (r"/mnt/trailing\04", r"/mnt/trailing\04"),
            (r"/mnt/\303\274", "/mnt/ü"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(unescape_mountinfo(input), expected);
        }
    }

    #[test]
    fn mount_entry_from_selects_the_top_mount_at_a_path() {
        let test_cases = vec![
            ("", "/mnt", None),
            ("41 1 0:41 / /other rw - fuse old rw", "/mnt", None),
            (
                "41 1 0:41 / /mnt rw - fuse old rw\n42 1 43:0 / /mnt rw - erofs new rw",
                "/mnt",
                Some(("43:0", "erofs")),
            ),
            (
                "41 1 0:41 / /mnt\\040image rw shared:1 - fuse.nydus image rw\nmalformed",
                "/mnt image",
                Some(("0:41", "fuse.nydus")),
            ),
        ];

        for (mountinfo, target, expected) in test_cases {
            assert_eq!(
                mount_entry_from(mountinfo, Path::new(target)),
                expected.map(|(dev, kind)| (dev.into(), kind.into()))
            );
        }
    }

    #[test]
    fn mount_entry_of_reads_the_mount_table_of_this_process() {
        assert!(mount_entry_of(Path::new("/")).unwrap().is_some());
        assert!(mount_entry_of(Path::new("/definitely/not/a/mountpoint"))
            .unwrap()
            .is_none());
    }
}
