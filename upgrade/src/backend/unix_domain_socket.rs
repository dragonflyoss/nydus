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
