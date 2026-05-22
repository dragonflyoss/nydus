use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Mutex;

const CHUNKMAP_MAGIC: [u8; 8] = *b"LPCM0001";
const CHUNKMAP_VERSION: u32 = 1;
const CHUNKMAP_HEADER_SIZE: u64 = 16;

struct ChunkMapState {
    file: File,
    bits: Vec<u8>,
    chunk_count: usize,
}

pub struct ChunkMap {
    state: Mutex<ChunkMapState>,
}

impl ChunkMap {
    pub fn open(path: &Path, chunk_count: usize) -> io::Result<Self> {
        let bytes_len = chunk_count.div_ceil(8);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let bits = if file.metadata()?.len() == 0 {
            let bits = vec![0u8; bytes_len];
            write_header(&mut file, chunk_count)?;
            file.write_all(&bits)?;
            file.flush()?;
            bits
        } else {
            let existing = read_header(&mut file)?;
            if existing != chunk_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "chunkmap {} chunk count mismatch: expected {}, got {}",
                        path.display(),
                        chunk_count,
                        existing
                    ),
                ));
            }

            let mut bits = vec![0u8; bytes_len];
            file.read_exact(&mut bits)?;
            bits
        };

        Ok(Self {
            state: Mutex::new(ChunkMapState {
                file,
                bits,
                chunk_count,
            }),
        })
    }

    pub fn is_ready(&self, index: usize) -> io::Result<bool> {
        let state = self.state.lock().unwrap();
        ensure_index(index, state.chunk_count)?;
        Ok(state.bits[index / 8] & (1u8 << (index % 8)) != 0)
    }

    pub fn set_ready(&self, index: usize) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        ensure_index(index, state.chunk_count)?;
        let byte_index = index / 8;
        let bit_mask = 1u8 << (index % 8);
        if state.bits[byte_index] & bit_mask != 0 {
            return Ok(());
        }

        state.bits[byte_index] |= bit_mask;
        state.file.write_at(
            &[state.bits[byte_index]],
            CHUNKMAP_HEADER_SIZE + byte_index as u64,
        )?;
        state.file.flush()?;
        Ok(())
    }
}

fn ensure_index(index: usize, chunk_count: usize) -> io::Result<()> {
    if index >= chunk_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("chunk index {} out of range {}", index, chunk_count),
        ));
    }
    Ok(())
}

fn write_header(file: &mut File, chunk_count: usize) -> io::Result<()> {
    file.write_all(&CHUNKMAP_MAGIC)?;
    file.write_all(&CHUNKMAP_VERSION.to_le_bytes())?;
    file.write_all(&(chunk_count as u32).to_le_bytes())?;
    Ok(())
}

fn read_header(file: &mut File) -> io::Result<usize> {
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if magic != CHUNKMAP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid chunkmap magic",
        ));
    }

    let mut version = [0u8; 4];
    file.read_exact(&mut version)?;
    if u32::from_le_bytes(version) != CHUNKMAP_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported chunkmap version",
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
    fn chunkmap_persists_ready_bits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob.chunkmap");

        let map = ChunkMap::open(&path, 10).unwrap();
        assert!(!map.is_ready(3).unwrap());
        map.set_ready(3).unwrap();
        map.set_ready(9).unwrap();
        assert!(map.is_ready(3).unwrap());
        assert!(map.is_ready(9).unwrap());

        let reopened = ChunkMap::open(&path, 10).unwrap();
        assert!(reopened.is_ready(3).unwrap());
        assert!(reopened.is_ready(9).unwrap());
        assert!(!reopened.is_ready(2).unwrap());
    }
}
