// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    os::{fd::RawFd, unix::net::UnixStream},
    path::PathBuf,
};

use sendfd::{RecvWithFd, SendWithFd};

use super::{Result, StorageBackend, StorageBackendErr};

pub struct UdsStorageBackend {
    socket_path: PathBuf,
}

impl UdsStorageBackend {
    pub fn new(socket_path: PathBuf) -> Self {
        UdsStorageBackend { socket_path }
    }
}

const MAX_STATE_DATA_LENGTH: usize = 1024 * 32;

impl StorageBackend for UdsStorageBackend {
    fn save(&mut self, fds: &[RawFd], data: &[u8]) -> Result<usize> {
        if fds.is_empty() {
            return Err(StorageBackendErr::NoEnoughFds);
        }

        let socket =
            UnixStream::connect(&self.socket_path).map_err(StorageBackendErr::CreateUnixStream)?;
        let len = socket
            .send_with_fd(data, fds)
            .map_err(StorageBackendErr::SendFd)?;

        Ok(len)
    }

    fn restore(&mut self) -> Result<(Vec<RawFd>, Vec<u8>)> {
        let mut data = vec![0u8; MAX_STATE_DATA_LENGTH];
        let mut fds = vec![0i32; 16];
        let socket =
            UnixStream::connect(&self.socket_path).map_err(StorageBackendErr::CreateUnixStream)?;
        let (_, fds_cnt) = socket
            .recv_with_fd(data.as_mut_slice(), fds.as_mut_slice())
            .map_err(StorageBackendErr::RecvFd)?;

        if fds.is_empty() {
            return Err(StorageBackendErr::NoEnoughFds);
        }
        fds.truncate(fds_cnt);
        Ok((fds, data))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_new_stores_socket_path() {
        let path = PathBuf::from("/tmp/test_nydus_uds.sock");
        let backend = UdsStorageBackend::new(path.clone());
        assert_eq!(backend.socket_path, path);
    }

    #[test]
    fn test_save_empty_fds_returns_no_enough_fds() {
        let mut backend = UdsStorageBackend::new(PathBuf::from("/nonexistent.sock"));
        let result = backend.save(&[], b"state-data");
        assert!(matches!(result, Err(StorageBackendErr::NoEnoughFds)));
    }

    #[test]
    fn test_save_invalid_socket_path_returns_create_unix_stream_error() {
        let mut backend = UdsStorageBackend::new(PathBuf::from("/nonexistent/dir/test.sock"));
        // Provide a non-empty fds slice so the empty-fds guard does not fire;
        // the connect() call must fail first.
        let result = backend.save(&[0i32], b"data");
        assert!(matches!(
            result,
            Err(StorageBackendErr::CreateUnixStream(_))
        ));
    }

    #[test]
    fn test_restore_invalid_socket_path_returns_create_unix_stream_error() {
        let mut backend = UdsStorageBackend::new(PathBuf::from("/nonexistent/dir/test.sock"));
        let result = backend.restore();
        assert!(matches!(
            result,
            Err(StorageBackendErr::CreateUnixStream(_))
        ));
    }
}
