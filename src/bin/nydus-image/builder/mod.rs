// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

pub mod directory;
pub mod stargz;

use anyhow::Result;

use crate::core::context::BuildContext;

pub trait Builder {
    fn build(&mut self, ctx: &mut BuildContext) -> Result<(Vec<String>, usize)>;
}
