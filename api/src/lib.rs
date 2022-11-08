// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! APIs for the Nydus Image Service
//!
//! The `nydus-api` crate defines API and related data structures for Nydus Image Service.
//! All data structures used by the API are encoded in JSON format.

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[cfg(feature = "handler")]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate nydus_error;

pub mod config;
pub use config::*;
pub mod http;
pub use self::http::*;

#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_common;
#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_v1;
#[cfg(feature = "handler")]
pub(crate) mod http_endpoint_v2;
#[cfg(feature = "handler")]
pub(crate) mod http_handler;

#[cfg(feature = "handler")]
pub use http_handler::{
    extract_query_part, start_http_thread, EndpointHandler, HttpResult, HttpRoutes, HTTP_ROUTES,
};
