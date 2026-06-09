use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Mutex;

const GROUPMAP_MAGIC: [u8; 8] = *b"LPGM0001";
const GROUPMAP_VERSION: u32 = 1;
const GROUPMAP_HEADER_SIZE: u64 = 16;

struct GroupMapState {
    file: File,
    bits: Vec<u8>,
    group_count: usize,
}

pub struct GroupMap {
    state: Mutex<GroupMapState>,
}

impl GroupMap {
    pub fn open(path: &Path, group_count: usize) -> io::Result<Self> {
        let bytes_len = group_count.div_ceil(8);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let bits = if file.metadata()?.len() == 0 {
            let bits = vec![0u8; bytes_len];
            write_header(&mut file, group_count)?;
            file.write_all(&bits)?;
            file.flush()?;
            bits
        } else {
            let existing = read_header(&mut file)?;
            if existing != group_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "groupmap {} group count mismatch: expected {}, got {}",
                        path.display(),
                        group_count,
                        existing
                    ),
                ));
            }

            let mut bits = vec![0u8; bytes_len];
            file.read_exact(&mut bits)?;
            bits
        };

        Ok(Self {
            state: Mutex::new(GroupMapState {
                file,
                bits,
                group_count,
            }),
        })
    }

    pub fn is_ready(&self, index: usize) -> io::Result<bool> {
        let state = self.state.lock().unwrap();
        ensure_index(index, state.group_count)?;
        Ok(state.bits[index / 8] & (1u8 << (index % 8)) != 0)
    }

    pub fn set_ready(&self, index: usize) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        ensure_index(index, state.group_count)?;
        let byte_index = index / 8;
        let bit_mask = 1u8 << (index % 8);
        if state.bits[byte_index] & bit_mask != 0 {
            return Ok(());
        }

        state.bits[byte_index] |= bit_mask;
        state.file.write_at(
            &[state.bits[byte_index]],
            GROUPMAP_HEADER_SIZE + byte_index as u64,
        )?;
        state.file.flush()?;
        Ok(())
    }
}

fn ensure_index(index: usize, group_count: usize) -> io::Result<()> {
    if index >= group_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("group index {index} out of range {group_count}"),
        ));
    }
    Ok(())
}

fn write_header(file: &mut File, group_count: usize) -> io::Result<()> {
    file.write_all(&GROUPMAP_MAGIC)?;
    file.write_all(&GROUPMAP_VERSION.to_le_bytes())?;
    file.write_all(&(group_count as u32).to_le_bytes())?;
    Ok(())
}

fn read_header(file: &mut File) -> io::Result<usize> {
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if magic != GROUPMAP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid groupmap magic",
        ));
    }

    let mut version = [0u8; 4];
    file.read_exact(&mut version)?;
    if u32::from_le_bytes(version) != GROUPMAP_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported groupmap version",
        ));
    }

    let mut count = [0u8; 4];
    file.read_exact(&mut count)?;
    Ok(u32::from_le_bytes(count) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn groupmap_persists_ready_bits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.groupmap");

        let map = GroupMap::open(&path, 10).unwrap();
        assert!(!map.is_ready(3).unwrap());
        map.set_ready(3).unwrap();
        map.set_ready(9).unwrap();
        assert!(map.is_ready(3).unwrap());
        assert!(map.is_ready(9).unwrap());

        let reopened = GroupMap::open(&path, 10).unwrap();
        assert!(reopened.is_ready(3).unwrap());
        assert!(reopened.is_ready(9).unwrap());
        assert!(!reopened.is_ready(2).unwrap());
    }
}
