// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub trait ByteSize {
    fn byte_size(&self) -> usize;
}

impl ByteSize for OsString {
    fn byte_size(&self) -> usize {
        self.as_bytes().len()
    }
}

impl ByteSize for OsStr {
    fn byte_size(&self) -> usize {
        self.as_bytes().len()
    }
}

impl ByteSize for PathBuf {
    fn byte_size(&self) -> usize {
        self.as_os_str().byte_size()
    }
}
