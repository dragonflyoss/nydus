// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate micro_http;
extern crate vmm_sys_util;
#[macro_use]
extern crate lazy_static;
extern crate url;

pub mod http;
pub mod http_endpoint;
