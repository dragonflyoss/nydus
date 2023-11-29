// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display, Formatter};
use std::io::Error;

mod db;

/// Error codes related to local cas.
#[derive(Debug)]
pub enum CasError {
    Io(Error),
    Db(rusqlite::Error),
    R2D2(r2d2::Error),
}

impl Display for CasError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CasError::Io(e) => write!(f, "{}", e),
            CasError::Db(e) => write!(f, "{}", e),
            CasError::R2D2(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CasError {}

impl From<rusqlite::Error> for CasError {
    fn from(e: rusqlite::Error) -> Self {
        CasError::Db(e)
    }
}

impl From<r2d2::Error> for CasError {
    fn from(e: r2d2::Error) -> Self {
        CasError::R2D2(e)
    }
}

impl From<Error> for CasError {
    fn from(e: Error) -> Self {
        CasError::Io(e)
    }
}

/// Specialized `Result` for local cas.
type Result<T> = std::result::Result<T, CasError>;
