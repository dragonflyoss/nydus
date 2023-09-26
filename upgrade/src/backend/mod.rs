use std::{io, os::fd::RawFd};

pub mod unix_domain_socket;

#[derive(thiserror::Error, Debug)]
pub enum StorageBackendErr {
    #[error("failed to create UnixStream, {0}")]
    CreateUnixStream(io::Error),
    #[error("failed to send fd over UnixStream, {0}")]
    SendFd(io::Error),
    #[error("failed to receive fd over UnixStream, {0}")]
    RecvFd(io::Error),
    #[error("no enough fds")]
    NoEnoughFds,
}

pub type Result<T> = std::result::Result<T, StorageBackendErr>;

/// StorageBackend trait is used to save and restore the fuse fds and fuse state data for online upgrade.
pub trait StorageBackend: Send + Sync {
    /// Save the fuse fds and fuse state data for online upgrade.
    /// Returns the length of bytes of fuse state data.
    fn save(&mut self, fds: &[RawFd], data: &[u8]) -> Result<usize>;

    /// Restore the fuse fds and fuse state data for online upgrade.
    /// Returns the length of bytes of fuse state data and the length of fds.
    fn restore(&mut self, fds: &mut Vec<RawFd>, data: &mut Vec<u8>) -> Result<(usize, usize)>;
}

#[cfg(test)]
mod test {

    #[test]
    fn test_storage_backend() {
        use std::os::fd::RawFd;

        use crate::backend::{Result, StorageBackend};

        #[derive(Default)]
        struct TestStorageBackend {
            fds: Vec<RawFd>,
            data: Vec<u8>,
        }

        impl StorageBackend for TestStorageBackend {
            fn save(&mut self, fds: &[RawFd], data: &[u8]) -> Result<usize> {
                self.fds = Vec::new();
                fds.iter().for_each(|fd| self.fds.push(*fd));

                self.data = vec![0u8; data.len()];
                self.data.clone_from_slice(data);

                Ok(self.data.len())
            }

            fn restore(
                &mut self,
                fds: &mut Vec<RawFd>,
                data: &mut Vec<u8>,
            ) -> Result<(usize, usize)> {
                fds.truncate(self.fds.len());
                fds.copy_from_slice(&self.fds);

                data.truncate(self.data.len());
                data.copy_from_slice(&self.data);

                Ok((data.len(), fds.len()))
            }
        }

        const FDS_LEN: usize = 10;
        const DATA_LEN: usize = 5;
        let fds = [5 as RawFd; FDS_LEN];
        let data: [u8; DATA_LEN] = [7, 8, 9, 10, 12];

        let mut backend: Box<dyn StorageBackend> = Box::new(TestStorageBackend::default());
        let saved_data_len = backend.save(&fds, &data).unwrap();
        assert_eq!(saved_data_len, DATA_LEN);

        let mut restored_fds = vec![0 as RawFd; 100];
        let mut restored_data = vec![0 as u8; 100];
        let (restored_data_len, restored_fds_len) = backend
            .restore(&mut restored_fds, &mut restored_data)
            .unwrap();
        assert_eq!(restored_data_len, DATA_LEN);
        assert_eq!(restored_fds_len, FDS_LEN);

        restored_data.truncate(restored_data_len);
        restored_fds.truncate(restored_fds_len);
        assert_eq!(restored_data, data);
        assert_eq!(restored_fds, fds);
    }
}
