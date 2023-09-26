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

impl StorageBackend for UdsStorageBackend {
    fn save(&mut self, fds: &[RawFd], data: &[u8]) -> Result<usize> {
        if fds.len() < 1 {
            return Err(StorageBackendErr::NoEnoughFds);
        }

        let socket =
            UnixStream::connect(&self.socket_path).map_err(StorageBackendErr::CreateUnixStream)?;
        let len = socket
            .send_with_fd(data, fds)
            .map_err(StorageBackendErr::SendFd)?;

        Ok(len)
    }

    fn restore(&mut self, fds: &mut Vec<RawFd>, data: &mut Vec<u8>) -> Result<(usize, usize)> {
        let socket =
            UnixStream::connect(&self.socket_path).map_err(StorageBackendErr::CreateUnixStream)?;
        let len_pair = socket
            .recv_with_fd(data, fds)
            .map_err(StorageBackendErr::RecvFd)?;

        if fds.len() < 1 {
            return Err(StorageBackendErr::NoEnoughFds);
        }

        Ok(len_pair)
    }
}
