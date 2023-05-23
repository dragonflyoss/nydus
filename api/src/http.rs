// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::mpsc::{RecvError, SendError};

use serde::Deserialize;
use serde_json::Error as SerdeError;

use crate::BlobCacheEntry;

/// Errors related to Metrics.
#[derive(Debug)]
pub enum MetricsError {
    /// Non-exist counter.
    NoCounter,
    /// Failed to serialize message.
    Serialize(SerdeError),
}

/// Mount a filesystem.
#[derive(Clone, Deserialize, Debug)]
pub struct ApiMountCmd {
    /// Path to source of the filesystem.
    pub source: String,
    /// Type of filesystem.
    #[serde(default)]
    pub fs_type: String,
    /// Configuration for the filesystem.
    pub config: String,
    /// List of files to prefetch.
    #[serde(default)]
    pub prefetch_files: Option<Vec<String>>,
}

/// Umount a mounted filesystem.
#[derive(Clone, Deserialize, Debug)]
pub struct ApiUmountCmd {
    /// Path of mountpoint.
    pub mountpoint: String,
}

/// Set/update daemon configuration.
#[derive(Clone, Deserialize, Debug)]
pub struct DaemonConf {
    /// Logging level: Off, Error, Warn, Info, Debug, Trace.
    pub log_level: String,
}

/// Identifier for cached blob objects.
///
/// Domains are used to control the blob sharing scope. All blobs associated with the same domain
/// will be shared/reused, but blobs associated with different domains are isolated.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlobCacheObjectId {
    /// Domain identifier for the object.
    #[serde(default)]
    pub domain_id: String,
    /// Blob identifier for the object.
    #[serde(default)]
    pub blob_id: String,
}

#[derive(Debug)]
pub enum ApiRequest {
    /// Set daemon configuration.
    ConfigureDaemon(DaemonConf),
    /// Get daemon information.
    GetDaemonInfo,
    /// Get daemon global events.
    GetEvents,
    /// Stop the daemon.
    Exit,
    /// Start the daemon.
    Start,
    /// Send fuse fd to new daemon.
    SendFuseFd,
    /// Take over fuse fd from old daemon instance.
    TakeoverFuseFd,

    // Filesystem Related
    /// Mount a filesystem.
    Mount(String, ApiMountCmd),
    /// Remount a filesystem.
    Remount(String, ApiMountCmd),
    /// Unmount a filesystem.
    Umount(String),

    /// Get storage backend metrics.
    ExportBackendMetrics(Option<String>),
    /// Get blob cache metrics.
    ExportBlobcacheMetrics(Option<String>),

    // Nydus API v1 requests
    /// Get filesystem global metrics.
    ExportFsGlobalMetrics(Option<String>),
    /// Get filesystem access pattern log.
    ExportFsAccessPatterns(Option<String>),
    /// Get filesystem backend information.
    ExportFsBackendInfo(String),
    /// Get filesystem file metrics.
    ExportFsFilesMetrics(Option<String>, bool),
    /// Get information about filesystem inflight requests.
    ExportFsInflightMetrics,

    // Nydus API v2
    /// Get daemon information excluding filesystem backends.
    GetDaemonInfoV2,
    /// Create a blob cache entry
    CreateBlobObject(Box<BlobCacheEntry>),
    /// Get information about blob cache entries
    GetBlobObject(BlobCacheObjectId),
    /// Delete a blob cache entry
    DeleteBlobObject(BlobCacheObjectId),
    /// Delete a blob cache file
    DeleteBlobFile(String),
}

/// Kinds for daemon related error messages.
#[derive(Debug)]
pub enum DaemonErrorKind {
    /// Service not ready yet.
    NotReady,
    /// Generic errors.
    Other(String),
    /// Message serialization/deserialization related errors.
    Serde(SerdeError),
    /// Unexpected event type.
    UnexpectedEvent(String),
    /// Can't upgrade the daemon.
    UpgradeManager,
    /// Unsupported requests.
    Unsupported,
}

/// Kinds for metrics related error messages.
#[derive(Debug)]
pub enum MetricsErrorKind {
    /// Generic daemon related errors.
    Daemon(DaemonErrorKind),
    /// Errors related to metrics implementation.
    Stats(MetricsError),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApiError {
    /// Daemon internal error
    DaemonAbnormal(DaemonErrorKind),
    /// Failed to get events information
    Events(String),
    /// Failed to get metrics information
    Metrics(MetricsErrorKind),
    /// Failed to mount filesystem
    MountFilesystem(DaemonErrorKind),
    /// Failed to send request to the API service
    RequestSend(SendError<Option<ApiRequest>>),
    /// Unrecognized payload content
    ResponsePayloadType,
    /// Failed to receive response from the API service
    ResponseRecv(RecvError),
    /// Failed to send wakeup notification
    Wakeup(io::Error),
}

/// Specialized `std::result::Result` for API replies.
pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Serialize)]
pub enum ApiResponsePayload {
    /// Filesystem backend metrics.
    BackendMetrics(String),
    /// Blobcache metrics.
    BlobcacheMetrics(String),
    /// Daemon version, configuration and status information in json.
    DaemonInfo(String),
    /// No data is sent on the channel.
    Empty,
    /// Global error events.
    Events(String),

    /// Filesystem global metrics, v1.
    FsGlobalMetrics(String),
    /// Filesystem per-file metrics, v1.
    FsFilesMetrics(String),
    /// Filesystem access pattern trace log, v1.
    FsFilesPatterns(String),
    // Filesystem Backend Information, v1.
    FsBackendInfo(String),
    // Filesystem Inflight Requests, v1.
    FsInflightMetrics(String),

    /// List of blob objects, v2
    BlobObjectList(String),
}

/// Specialized version of [`std::result::Result`] for value returned by backend services.
pub type ApiResponse = std::result::Result<ApiResponsePayload, ApiError>;

/// HTTP error messages sent back to the clients.
///
/// The `HttpError` object will be sent back to client with `format!("{:?}", http_error)`.
/// So unfortunately it implicitly becomes parts of the API, please keep it stable.
#[derive(Debug)]
pub enum HttpError {
    // Daemon common related errors
    /// Invalid HTTP request
    BadRequest,
    /// Failed to configure the daemon.
    Configure(ApiError),
    /// Failed to query information about daemon.
    DaemonInfo(ApiError),
    /// Failed to query global events.
    Events(ApiError),
    /// No handler registered for HTTP request URI
    NoRoute,
    /// Failed to parse HTTP request message body
    ParseBody(SerdeError),
    /// Query parameter is missed from the HTTP request.
    QueryString(String),

    /// Failed to mount filesystem.
    Mount(ApiError),
    /// Failed to remount filesystem.
    Upgrade(ApiError),

    // Metrics related errors
    /// Failed to get backend metrics.
    BackendMetrics(ApiError),
    /// Failed to get blobcache metrics.
    BlobcacheMetrics(ApiError),

    // Filesystem related errors (v1)
    /// Failed to get filesystem backend information
    FsBackendInfo(ApiError),
    /// Failed to get filesystem per-file metrics.
    FsFilesMetrics(ApiError),
    /// Failed to get global metrics.
    GlobalMetrics(ApiError),
    /// Failed to get information about inflight request
    InflightMetrics(ApiError),
    /// Failed to get filesystem file access trace.
    Pattern(ApiError),

    // Blob cache management related errors (v2)
    /// Failed to create blob object
    CreateBlobObject(ApiError),
    /// Failed to delete blob object
    DeleteBlobObject(ApiError),
    /// Failed to delete blob file
    DeleteBlobFile(ApiError),
    /// Failed to list existing blob objects
    GetBlobObjects(ApiError),
}

#[derive(Serialize, Debug)]
pub(crate) struct ErrorMessage {
    pub code: String,
    pub message: String,
}

impl From<ErrorMessage> for Vec<u8> {
    fn from(msg: ErrorMessage) -> Self {
        // Safe to unwrap since `ErrorMessage` must succeed in serialization
        serde_json::to_vec(&msg).unwrap()
    }
}
