// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

/// Configuration file format version 2, based on Toml.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigV2 {
    /// Configuration file format version number, must be 2.
    pub version: u32,
    /// Identifier for the instance.
    #[serde(default)]
    pub id: String,
    /// Configuration information for storage backend.
    pub backend: Option<BackendConfigV2>,
    /// Configuration information for local cache system.
    pub cache: Option<CacheConfigV2>,
    /// Configuration information for RAFS filesystem.
    pub rafs: Option<RafsConfigV2>,
    /// Internal runtime configuration.
    #[serde(skip)]
    pub internal: ConfigV2Internal,
}

impl Default for ConfigV2 {
    fn default() -> Self {
        ConfigV2 {
            version: 2,
            id: String::new(),
            backend: None,
            cache: None,
            rafs: None,
            internal: ConfigV2Internal::default(),
        }
    }
}

impl ConfigV2 {
    /// Create a new instance of `ConfigV2` object.
    pub fn new(id: &str) -> Self {
        ConfigV2 {
            version: 2,
            id: id.to_string(),
            backend: None,
            cache: None,
            rafs: None,
            internal: ConfigV2Internal::default(),
        }
    }

    /// Create a new configuration object for `backend-localfs` and `filecache`.
    pub fn new_localfs(id: &str, dir: &str) -> Result<Self> {
        let content = format!(
            r#"
        version = 2
        id = "{}"
        backend.type = "localfs"
        backend.localfs.dir = "{}"
        cache.type = "filecache"
        cache.compressed = false
        cache.validate = false
        cache.filecache.work_dir = "{}"
        "#,
            id, dir, dir
        );

        Self::from_str(&content)
    }

    /// Read configuration information from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let md = fs::metadata(path.as_ref())?;
        if md.len() > 0x100000 {
            return Err(Error::new(
                ErrorKind::Other,
                "configuration file size is too big",
            ));
        }
        let content = fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Validate the configuration object.
    pub fn validate(&self) -> bool {
        if self.version != 2 {
            return false;
        }
        if let Some(backend_cfg) = self.backend.as_ref() {
            if !backend_cfg.validate() {
                return false;
            }
        }
        if let Some(cache_cfg) = self.cache.as_ref() {
            if !cache_cfg.validate() {
                return false;
            }
        }
        if let Some(rafs_cfg) = self.rafs.as_ref() {
            if !rafs_cfg.validate() {
                return false;
            }
        }

        true
    }

    /// Get configuration information for storage backend.
    pub fn get_backend_config(&self) -> Result<&BackendConfigV2> {
        self.backend.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "no configuration information for backend",
            )
        })
    }

    /// Get configuration information for cache subsystem.
    pub fn get_cache_config(&self) -> Result<&CacheConfigV2> {
        self.cache.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "no configuration information for cache",
            )
        })
    }

    /// Get cache working directory.
    pub fn get_cache_working_directory(&self) -> Result<String> {
        let cache = self.get_cache_config()?;
        if cache.is_filecache() {
            if let Some(c) = cache.file_cache.as_ref() {
                return Ok(c.work_dir.clone());
            }
        } else if cache.is_fscache() {
            if let Some(c) = cache.fs_cache.as_ref() {
                return Ok(c.work_dir.clone());
            }
        }

        Err(Error::new(
            ErrorKind::NotFound,
            "no working directory configured",
        ))
    }

    /// Get configuration information for RAFS filesystem.
    pub fn get_rafs_config(&self) -> Result<&RafsConfigV2> {
        self.rafs.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "no configuration information for rafs",
            )
        })
    }

    /// Clone the object with all secrets removed.
    pub fn clone_without_secrets(&self) -> Self {
        let mut cfg = self.clone();

        if let Some(backend_cfg) = cfg.backend.as_mut() {
            if let Some(oss_cfg) = backend_cfg.oss.as_mut() {
                oss_cfg.access_key_id = String::new();
                oss_cfg.access_key_secret = String::new();
            }
            if let Some(registry_cfg) = backend_cfg.registry.as_mut() {
                registry_cfg.auth = None;
                registry_cfg.registry_token = None;
            }
        }

        cfg
    }

    /// Check whether chunk digest validation is enabled or not.
    pub fn is_chunk_validation_enabled(&self) -> bool {
        let mut validation = if let Some(cache) = &self.cache {
            cache.cache_validate
        } else {
            false
        };
        if let Some(rafs) = &self.rafs {
            if rafs.validate {
                validation = true;
            }
        }

        validation
    }

    /// Check whether fscache is enabled or not.
    pub fn is_fs_cache(&self) -> bool {
        if let Some(cache) = self.cache.as_ref() {
            cache.fs_cache.is_some()
        } else {
            false
        }
    }

    /// Fill authorization for registry backend.
    pub fn update_registry_auth_info(&mut self, auth: &Option<String>) {
        if let Some(auth) = auth {
            if let Some(backend) = self.backend.as_mut() {
                if let Some(registry) = backend.registry.as_mut() {
                    registry.auth = Some(auth.to_string());
                }
            }
        }
    }
}

impl FromStr for ConfigV2 {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<ConfigV2> {
        if let Ok(v) = serde_json::from_str::<ConfigV2>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        if let Ok(v) = toml::from_str::<ConfigV2>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        if let Ok(v) = serde_json::from_str::<RafsConfig>(s) {
            if let Ok(v) = ConfigV2::try_from(v) {
                if v.validate() {
                    return Ok(v);
                }
            }
        }
        Err(Error::new(
            ErrorKind::InvalidInput,
            "failed to parse configuration information",
        ))
    }
}

/// Configuration information for storage backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendConfigV2 {
    /// Type of storage backend.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Configuration for local disk backend.
    pub localdisk: Option<LocalDiskConfig>,
    /// Configuration for local filesystem backend.
    pub localfs: Option<LocalFsConfig>,
    /// Configuration for OSS backend.
    pub oss: Option<OssConfig>,
    /// Configuration for S3 backend.
    pub s3: Option<S3Config>,
    /// Configuration for container registry backend.
    pub registry: Option<RegistryConfig>,
    /// Configuration for local http proxy.
    #[serde(rename = "http-proxy")]
    pub http_proxy: Option<HttpProxyConfig>,
}

impl BackendConfigV2 {
    /// Validate storage backend configuration.
    pub fn validate(&self) -> bool {
        match self.backend_type.as_str() {
            "localdisk" => match self.localdisk.as_ref() {
                Some(v) => {
                    if v.device_path.is_empty() {
                        return false;
                    }
                }
                None => return false,
            },
            "localfs" => match self.localfs.as_ref() {
                Some(v) => {
                    if v.blob_file.is_empty() && v.dir.is_empty() {
                        return false;
                    }
                }
                None => return false,
            },
            "oss" => match self.oss.as_ref() {
                Some(v) => {
                    if v.endpoint.is_empty() || v.bucket_name.is_empty() {
                        return false;
                    }
                }
                None => return false,
            },
            "s3" => match self.s3.as_ref() {
                Some(v) => {
                    if v.region.is_empty() || v.bucket_name.is_empty() {
                        return false;
                    }
                }
                None => return false,
            },
            "registry" => match self.registry.as_ref() {
                Some(v) => {
                    if v.host.is_empty() || v.repo.is_empty() {
                        return false;
                    }
                }
                None => return false,
            },

            "http-proxy" => match self.http_proxy.as_ref() {
                Some(v) => {
                    let is_valid_unix_socket_path = |path: &str| {
                        let path = Path::new(path);
                        path.is_absolute() && path.exists()
                    };
                    if v.addr.is_empty()
                        || !(v.addr.starts_with("http://")
                            || v.addr.starts_with("https://")
                            || is_valid_unix_socket_path(&v.addr))
                    {
                        return false;
                    }

                    // check if v.path is valid url path format
                    if Path::new(&v.path).join("any_blob_id").to_str().is_none() {
                        return false;
                    }
                }
                None => return false,
            },
            _ => return false,
        }

        true
    }

    /// Get configuration information for localdisk
    pub fn get_localdisk_config(&self) -> Result<&LocalDiskConfig> {
        if &self.backend_type != "localdisk" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 'localdisk'",
            ))
        } else {
            self.localdisk.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for localdisk",
                )
            })
        }
    }

    /// Get configuration information for localfs
    pub fn get_localfs_config(&self) -> Result<&LocalFsConfig> {
        if &self.backend_type != "localfs" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 'localfs'",
            ))
        } else {
            self.localfs.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for localfs",
                )
            })
        }
    }

    /// Get configuration information for OSS
    pub fn get_oss_config(&self) -> Result<&OssConfig> {
        if &self.backend_type != "oss" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 'oss'",
            ))
        } else {
            self.oss.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for OSS",
                )
            })
        }
    }

    /// Get configuration information for S3
    pub fn get_s3_config(&self) -> Result<&S3Config> {
        if &self.backend_type != "s3" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 's3'",
            ))
        } else {
            self.s3.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for s3",
                )
            })
        }
    }

    /// Get configuration information for Registry
    pub fn get_registry_config(&self) -> Result<&RegistryConfig> {
        if &self.backend_type != "registry" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 'registry'",
            ))
        } else {
            self.registry.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for registry",
                )
            })
        }
    }

    /// Get configuration information for http proxy
    pub fn get_http_proxy_config(&self) -> Result<&HttpProxyConfig> {
        if &self.backend_type != "http-proxy" {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "backend type is not 'http-proxy'",
            ))
        } else {
            self.http_proxy.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for http-proxy",
                )
            })
        }
    }
}

/// Configuration information for localdisk storage backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalDiskConfig {
    /// Mounted block device path or original localdisk image file path.
    #[serde(default)]
    pub device_path: String,
    /// Disable discover blob objects by scanning GPT table.
    #[serde(default)]
    pub disable_gpt: bool,
}

/// Configuration information for localfs storage backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalFsConfig {
    /// Blob file to access.
    #[serde(default)]
    pub blob_file: String,
    /// Dir to hold blob files. Used when 'blob_file' is not specified.
    #[serde(default)]
    pub dir: String,
    /// Alternative dirs to search for blobs.
    #[serde(default)]
    pub alt_dirs: Vec<String>,
}

/// OSS configuration information to access blobs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OssConfig {
    /// Oss http scheme, either 'http' or 'https'
    #[serde(default = "default_http_scheme")]
    pub scheme: String,
    /// Oss endpoint
    pub endpoint: String,
    /// Oss bucket name
    pub bucket_name: String,
    /// Prefix object_prefix to OSS object key, for example the simulation of subdirectory:
    /// - object_key: sha256:xxx
    /// - object_prefix: nydus/
    /// - object_key with object_prefix: nydus/sha256:xxx
    #[serde(default)]
    pub object_prefix: String,
    /// Oss access key
    #[serde(default)]
    pub access_key_id: String,
    /// Oss secret
    #[serde(default)]
    pub access_key_secret: String,
    /// Skip SSL certificate validation for HTTPS scheme.
    #[serde(default)]
    pub skip_verify: bool,
    /// Drop the read request once http request timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub timeout: u32,
    /// Drop the read request once http connection timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub connect_timeout: u32,
    /// Retry count when read request failed.
    #[serde(default)]
    pub retry_limit: u8,
    /// Enable HTTP proxy for the read request.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Enable mirrors for the read request.
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
}

/// S3 configuration information to access blobs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct S3Config {
    /// S3 http scheme, either 'http' or 'https'
    #[serde(default = "default_http_scheme")]
    pub scheme: String,
    /// S3 endpoint
    pub endpoint: String,
    /// S3 region
    pub region: String,
    /// S3 bucket name
    pub bucket_name: String,
    /// Prefix object_prefix to S3 object key, for example the simulation of subdirectory:
    /// - object_key: sha256:xxx
    /// - object_prefix: nydus/
    /// - object_key with object_prefix: nydus/sha256:xxx
    #[serde(default)]
    pub object_prefix: String,
    /// S3 access key
    #[serde(default)]
    pub access_key_id: String,
    /// S3 secret
    #[serde(default)]
    pub access_key_secret: String,
    /// Skip SSL certificate validation for HTTPS scheme.
    #[serde(default)]
    pub skip_verify: bool,
    /// Drop the read request once http request timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub timeout: u32,
    /// Drop the read request once http connection timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub connect_timeout: u32,
    /// Retry count when read request failed.
    #[serde(default)]
    pub retry_limit: u8,
    /// Enable HTTP proxy for the read request.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Enable mirrors for the read request.
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
}

/// Http proxy configuration information to access blobs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HttpProxyConfig {
    /// Address of http proxy server, like `http://xxx.xxx` or `https://xxx.xxx` or `/path/to/unix.sock`.
    pub addr: String,
    /// Path to access the blobs, like `/<_namespace>/<_repo>/blobs`.
    /// If the http proxy server is over unix socket, this field will be ignored.
    #[serde(default)]
    pub path: String,
    /// Skip SSL certificate validation for HTTPS scheme.
    #[serde(default)]
    pub skip_verify: bool,
    /// Drop the read request once http request timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub timeout: u32,
    /// Drop the read request once http connection timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub connect_timeout: u32,
    /// Retry count when read request failed.
    #[serde(default)]
    pub retry_limit: u8,
    /// Enable HTTP proxy for the read request.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Enable mirrors for the read request.
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
}

/// Container registry configuration information to access blobs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryConfig {
    /// Registry http scheme, either 'http' or 'https'
    #[serde(default = "default_http_scheme")]
    pub scheme: String,
    /// Registry url host
    pub host: String,
    /// Registry image name, like 'library/ubuntu'
    pub repo: String,
    /// Base64_encoded(username:password), the field should be sent to registry auth server to get a bearer token.
    #[serde(default)]
    pub auth: Option<String>,
    /// Skip SSL certificate validation for HTTPS scheme.
    #[serde(default)]
    pub skip_verify: bool,
    /// Drop the read request once http request timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub timeout: u32,
    /// Drop the read request once http connection timeout, in seconds.
    #[serde(default = "default_http_timeout")]
    pub connect_timeout: u32,
    /// Retry count when read request failed.
    #[serde(default)]
    pub retry_limit: u8,
    /// The field is a bearer token to be sent to registry to authorize registry requests.
    #[serde(default)]
    pub registry_token: Option<String>,
    /// The http scheme to access blobs. It is used to workaround some P2P subsystem
    /// that requires a different scheme than the registry.
    #[serde(default)]
    pub blob_url_scheme: String,
    /// Redirect blob access to a different host regardless of the one specified in 'host'.
    #[serde(default)]
    pub blob_redirected_host: String,
    /// Enable HTTP proxy for the read request.
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Enable mirrors for the read request.
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
}

/// Configuration information for blob cache manager.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheConfigV2 {
    /// Type of blob cache: "blobcache", "fscache" or "dummy"
    #[serde(default, rename = "type")]
    pub cache_type: String,
    /// Whether the data from the cache is compressed, not used anymore.
    #[serde(default, rename = "compressed")]
    pub cache_compressed: bool,
    /// Whether to validate data read from the cache.
    #[serde(default, rename = "validate")]
    pub cache_validate: bool,
    /// Configuration for blob level prefetch.
    #[serde(default)]
    pub prefetch: PrefetchConfigV2,
    /// Configuration information for file cache
    #[serde(rename = "filecache")]
    pub file_cache: Option<FileCacheConfig>,
    #[serde(rename = "fscache")]
    /// Configuration information for fscache
    pub fs_cache: Option<FsCacheConfig>,
}

impl CacheConfigV2 {
    /// Validate cache configuration information.
    pub fn validate(&self) -> bool {
        match self.cache_type.as_str() {
            "blobcache" | "filecache" => {
                if let Some(c) = self.file_cache.as_ref() {
                    if c.work_dir.is_empty() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            "fscache" => {
                if let Some(c) = self.fs_cache.as_ref() {
                    if c.work_dir.is_empty() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            "" | "dummycache" => {}
            _ => return false,
        }

        if self.prefetch.enable {
            if self.prefetch.batch_size > 0x10000000 {
                return false;
            }
            if self.prefetch.threads == 0 || self.prefetch.threads > 1024 {
                return false;
            }
        }

        true
    }

    /// Check whether the cache type is `filecache`
    pub fn is_filecache(&self) -> bool {
        self.cache_type == "blobcache" || self.cache_type == "filecache"
    }

    /// Check whether the cache type is `fscache`
    pub fn is_fscache(&self) -> bool {
        self.cache_type == "fscache"
    }

    /// Get configuration information for file cache.
    pub fn get_filecache_config(&self) -> Result<&FileCacheConfig> {
        if self.is_filecache() {
            self.file_cache.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "no configuration information for filecache",
                )
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "cache type is not 'filecache'",
            ))
        }
    }

    /// Get configuration information for fscache.
    pub fn get_fscache_config(&self) -> Result<&FsCacheConfig> {
        if self.is_fscache() {
            self.fs_cache.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "no configuration information for fscache",
                )
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "cache type is not 'fscache'",
            ))
        }
    }
}

/// Configuration information for file cache.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCacheConfig {
    /// Working directory to store state and cached files.
    #[serde(default = "default_work_dir")]
    pub work_dir: String,
    /// Deprecated: disable index mapping, keep it as false when possible.
    #[serde(default)]
    pub disable_indexed_map: bool,
    /// Enable encryption data written to the cache file.
    #[serde(default)]
    pub enable_encryption: bool,
    /// Enable convergent encryption for chunk deduplication.
    #[serde(default)]
    pub enable_convergent_encryption: bool,
    /// Key for data encryption, a heximal representation of [u8; 32].
    #[serde(default)]
    pub encryption_key: String,
}

impl FileCacheConfig {
    /// Get the working directory.
    pub fn get_work_dir(&self) -> Result<&str> {
        let path = fs::metadata(&self.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&self.work_dir)?;
                fs::metadata(&self.work_dir)
            })
            .map_err(|e| {
                log::error!("fail to stat filecache work_dir {}: {}", self.work_dir, e);
                e
            })?;

        if path.is_dir() {
            Ok(&self.work_dir)
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                format!("filecache work_dir {} is not a directory", self.work_dir),
            ))
        }
    }
}

/// Configuration information for fscache.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FsCacheConfig {
    /// Working directory to store state and cached files.
    #[serde(default = "default_work_dir")]
    pub work_dir: String,
}

impl FsCacheConfig {
    /// Get the working directory.
    pub fn get_work_dir(&self) -> Result<&str> {
        let path = fs::metadata(&self.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&self.work_dir)?;
                fs::metadata(&self.work_dir)
            })
            .map_err(|e| {
                log::error!("fail to stat fscache work_dir {}: {}", self.work_dir, e);
                e
            })?;

        if path.is_dir() {
            Ok(&self.work_dir)
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                format!("fscache work_dir {} is not a directory", self.work_dir),
            ))
        }
    }
}

/// Configuration information for RAFS filesystem.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RafsConfigV2 {
    /// Filesystem metadata cache mode.
    #[serde(default = "default_rafs_mode")]
    pub mode: String,
    /// Batch size to read data from storage cache layer.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Whether to validate data digest.
    #[serde(default)]
    pub validate: bool,
    /// Enable support of extended attributes.
    #[serde(default)]
    pub enable_xattr: bool,
    /// Record file operation metrics for each file.
    ///
    /// Better to keep it off in production environment due to possible resource consumption.
    #[serde(default)]
    pub iostats_files: bool,
    /// Record filesystem access pattern.
    #[serde(default)]
    pub access_pattern: bool,
    /// Record file name if file access trace log.
    #[serde(default)]
    pub latest_read_files: bool,
    /// Filesystem prefetching configuration.
    #[serde(default)]
    pub prefetch: PrefetchConfigV2,
}

impl RafsConfigV2 {
    /// Validate RAFS filesystem configuration information.
    pub fn validate(&self) -> bool {
        if self.mode != "direct" && self.mode != "cached" {
            return false;
        }
        if self.batch_size > 0x10000000 {
            return false;
        }
        if self.prefetch.enable {
            if self.prefetch.batch_size > 0x10000000 {
                return false;
            }
            if self.prefetch.threads == 0 || self.prefetch.threads > 1024 {
                return false;
            }
        }

        true
    }
}

/// Configuration information for blob data prefetching.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrefetchConfigV2 {
    /// Whether to enable blob data prefetching.
    pub enable: bool,
    /// Number of data prefetching working threads.
    #[serde(default = "default_prefetch_threads")]
    pub threads: usize,
    /// The batch size to prefetch data from backend.
    #[serde(default = "default_prefetch_batch_size")]
    pub batch_size: usize,
    /// Network bandwidth rate limit in unit of Bytes and Zero means no limit.
    #[serde(default)]
    pub bandwidth_limit: u32,
    /// Prefetch all data from backend.
    #[serde(default)]
    pub prefetch_all: bool,
}

/// Configuration information for network proxy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProxyConfig {
    /// Access remote storage backend via proxy, e.g. Dragonfly dfdaemon server URL.
    #[serde(default)]
    pub url: String,
    /// Proxy health checking endpoint.
    #[serde(default)]
    pub ping_url: String,
    /// Fallback to remote storage backend if proxy ping failed.
    #[serde(default = "default_true")]
    pub fallback: bool,
    /// Interval for proxy health checking, in seconds.
    #[serde(default = "default_check_interval")]
    pub check_interval: u64,
    /// Replace URL to http to request source registry with proxy, and allow fallback to https if the proxy is unhealthy.
    #[serde(default)]
    pub use_http: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            ping_url: String::new(),
            fallback: true,
            check_interval: 5,
            use_http: false,
        }
    }
}

/// Configuration for registry mirror.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MirrorConfig {
    /// Mirror server URL, for example http://127.0.0.1:65001.
    pub host: String,
    /// Ping URL to check mirror server health.
    #[serde(default)]
    pub ping_url: String,
    /// HTTP request headers to be passed to mirror server.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Interval for mirror health checking, in seconds.
    #[serde(default = "default_check_interval")]
    pub health_check_interval: u64,
    /// Maximum number of failures before marking a mirror as unusable.
    #[serde(default = "default_failure_limit")]
    pub failure_limit: u8,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            headers: HashMap::new(),
            health_check_interval: 5,
            failure_limit: 5,
            ping_url: String::new(),
        }
    }
}

/// Configuration information for a cached blob`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobCacheEntryConfigV2 {
    /// Configuration file format version number, must be 2.
    pub version: u32,
    /// Identifier for the instance.
    #[serde(default)]
    pub id: String,
    /// Configuration information for storage backend.
    #[serde(default)]
    pub backend: BackendConfigV2,
    /// Configuration information for local cache system.
    #[serde(default)]
    pub cache: CacheConfigV2,
    /// Optional file path for metadata blob.
    #[serde(default)]
    pub metadata_path: Option<String>,
}

impl BlobCacheEntryConfigV2 {
    /// Read configuration information from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let md = fs::metadata(path.as_ref())?;
        if md.len() > 0x100000 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "configuration file size is too big",
            ));
        }
        let content = fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Validate the configuration object.
    pub fn validate(&self) -> bool {
        if self.version != 2 {
            return false;
        }
        let config: ConfigV2 = self.into();
        config.validate()
    }
}

impl FromStr for BlobCacheEntryConfigV2 {
    type Err = Error;

    fn from_str(s: &str) -> Result<BlobCacheEntryConfigV2> {
        if let Ok(v) = serde_json::from_str::<BlobCacheEntryConfigV2>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        if let Ok(v) = toml::from_str::<BlobCacheEntryConfigV2>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        Err(Error::new(
            ErrorKind::InvalidInput,
            "failed to parse configuration information",
        ))
    }
}

impl From<&BlobCacheEntryConfigV2> for ConfigV2 {
    fn from(c: &BlobCacheEntryConfigV2) -> Self {
        ConfigV2 {
            version: c.version,
            id: c.id.clone(),
            backend: Some(c.backend.clone()),
            cache: Some(c.cache.clone()),
            rafs: None,
            internal: ConfigV2Internal::default(),
        }
    }
}

/// Internal runtime configuration.
#[derive(Clone, Debug)]
pub struct ConfigV2Internal {
    /// It's possible to access the raw or more blob objects.
    pub blob_accessible: Arc<AtomicBool>,
}

impl Default for ConfigV2Internal {
    fn default() -> Self {
        ConfigV2Internal {
            blob_accessible: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl PartialEq for ConfigV2Internal {
    fn eq(&self, other: &Self) -> bool {
        self.blob_accessible() == other.blob_accessible()
    }
}

impl Eq for ConfigV2Internal {}

impl ConfigV2Internal {
    /// Get the auto-probe flag.
    pub fn blob_accessible(&self) -> bool {
        self.blob_accessible.load(Ordering::Relaxed)
    }

    /// Set the auto-probe flag.
    pub fn set_blob_accessible(&self, accessible: bool) {
        self.blob_accessible.store(accessible, Ordering::Relaxed);
    }
}

/// Blob cache object type for nydus/rafs bootstrap blob.
pub const BLOB_CACHE_TYPE_META_BLOB: &str = "bootstrap";
/// Blob cache object type for nydus/rafs data blob.
pub const BLOB_CACHE_TYPE_DATA_BLOB: &str = "datablob";

/// Configuration information for a cached blob.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlobCacheEntry {
    /// Type of blob object, bootstrap or data blob.
    #[serde(rename = "type")]
    pub blob_type: String,
    /// Blob id.
    #[serde(rename = "id")]
    pub blob_id: String,
    /// Configuration information to generate blob cache object.
    #[serde(default, rename = "config")]
    pub(crate) blob_config_legacy: Option<BlobCacheEntryConfig>,
    /// Configuration information to generate blob cache object.
    #[serde(default, rename = "config_v2")]
    pub blob_config: Option<BlobCacheEntryConfigV2>,
    /// Domain id for the blob, which is used to group cached blobs into management domains.
    #[serde(default)]
    pub domain_id: String,
}

impl BlobCacheEntry {
    pub fn prepare_configuration_info(&mut self) -> bool {
        if self.blob_config.is_none() {
            if let Some(legacy) = self.blob_config_legacy.as_ref() {
                match legacy.try_into() {
                    Err(_) => return false,
                    Ok(v) => self.blob_config = Some(v),
                }
            }
        }

        match self.blob_config.as_ref() {
            None => false,
            Some(cfg) => cfg.cache.validate() && cfg.backend.validate(),
        }
    }
}

impl BlobCacheEntry {
    /// Read configuration information from a file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let md = fs::metadata(path.as_ref())?;
        if md.len() > 0x100000 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "configuration file size is too big",
            ));
        }
        let content = fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Validate the configuration object.
    pub fn validate(&self) -> bool {
        if self.blob_type != BLOB_CACHE_TYPE_META_BLOB
            && self.blob_type != BLOB_CACHE_TYPE_DATA_BLOB
        {
            log::warn!("invalid blob type {} for blob cache entry", self.blob_type);
            return false;
        }
        if let Some(config) = self.blob_config.as_ref() {
            if !config.validate() {
                return false;
            }
        }
        true
    }
}

impl FromStr for BlobCacheEntry {
    type Err = Error;

    fn from_str(s: &str) -> Result<BlobCacheEntry> {
        if let Ok(v) = serde_json::from_str::<BlobCacheEntry>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        if let Ok(v) = toml::from_str::<BlobCacheEntry>(s) {
            return if v.validate() {
                Ok(v)
            } else {
                Err(Error::new(ErrorKind::InvalidInput, "invalid configuration"))
            };
        }
        Err(Error::new(
            ErrorKind::InvalidInput,
            "failed to parse configuration information",
        ))
    }
}

/// Configuration information for a list of cached blob objects.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct BlobCacheList {
    /// List of blob configuration information.
    pub blobs: Vec<BlobCacheEntry>,
}

fn default_true() -> bool {
    true
}

fn default_http_scheme() -> String {
    "https".to_string()
}

fn default_http_timeout() -> u32 {
    5
}

fn default_check_interval() -> u64 {
    5
}

fn default_failure_limit() -> u8 {
    5
}

fn default_work_dir() -> String {
    ".".to_string()
}

pub fn default_batch_size() -> usize {
    128 * 1024
}

fn default_prefetch_batch_size() -> usize {
    1024 * 1024
}

fn default_prefetch_threads() -> usize {
    8
}

fn default_prefetch_all() -> bool {
    true
}

fn default_rafs_mode() -> String {
    "direct".to_string()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// For backward compatibility
////////////////////////////////////////////////////////////////////////////////////////////////////

/// Configuration information for storage backend.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct BackendConfig {
    /// Type of storage backend.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Configuration for storage backend.
    /// Possible value: `LocalFsConfig`, `RegistryConfig`, `OssConfig`, `LocalDiskConfig`.
    #[serde(rename = "config")]
    pub backend_config: Value,
}

impl TryFrom<&BackendConfig> for BackendConfigV2 {
    type Error = std::io::Error;

    fn try_from(value: &BackendConfig) -> std::result::Result<Self, Self::Error> {
        let mut config = BackendConfigV2 {
            backend_type: value.backend_type.clone(),
            localdisk: None,
            localfs: None,
            oss: None,
            s3: None,
            registry: None,
            http_proxy: None,
        };

        match value.backend_type.as_str() {
            "localdisk" => {
                config.localdisk = Some(serde_json::from_value(value.backend_config.clone())?);
            }
            "localfs" => {
                config.localfs = Some(serde_json::from_value(value.backend_config.clone())?);
            }
            "oss" => {
                config.oss = Some(serde_json::from_value(value.backend_config.clone())?);
            }
            "s3" => {
                config.s3 = Some(serde_json::from_value(value.backend_config.clone())?);
            }
            "registry" => {
                config.registry = Some(serde_json::from_value(value.backend_config.clone())?);
            }
            v => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported backend type '{}'", v),
                ))
            }
        }

        Ok(config)
    }
}

/// Configuration information for blob cache manager.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct CacheConfig {
    /// Type of blob cache: "blobcache", "fscache" or ""
    #[serde(default, rename = "type")]
    pub cache_type: String,
    /// Whether the data from the cache is compressed, not used anymore.
    #[serde(default, rename = "compressed")]
    pub cache_compressed: bool,
    /// Blob cache manager specific configuration: FileCacheConfig, FsCacheConfig.
    #[serde(default, rename = "config")]
    pub cache_config: Value,
    /// Whether to validate data read from the cache.
    #[serde(skip_serializing, skip_deserializing)]
    pub cache_validate: bool,
    /// Configuration for blob data prefetching.
    #[serde(skip_serializing, skip_deserializing)]
    pub prefetch_config: BlobPrefetchConfig,
}

impl TryFrom<&CacheConfig> for CacheConfigV2 {
    type Error = std::io::Error;

    fn try_from(v: &CacheConfig) -> std::result::Result<Self, Self::Error> {
        let mut config = CacheConfigV2 {
            cache_type: v.cache_type.clone(),
            cache_compressed: v.cache_compressed,
            cache_validate: v.cache_validate,
            prefetch: (&v.prefetch_config).into(),
            file_cache: None,
            fs_cache: None,
        };

        match v.cache_type.as_str() {
            "blobcache" | "filecache" => {
                config.file_cache = Some(serde_json::from_value(v.cache_config.clone())?);
            }
            "fscache" => {
                config.fs_cache = Some(serde_json::from_value(v.cache_config.clone())?);
            }
            "" => {}
            t => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported cache type '{}'", t),
                ))
            }
        }

        Ok(config)
    }
}

/// Configuration information to create blob cache manager.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct FactoryConfig {
    /// Id of the factory.
    #[serde(default)]
    pub id: String,
    /// Configuration for storage backend.
    pub backend: BackendConfig,
    /// Configuration for blob cache manager.
    #[serde(default)]
    pub cache: CacheConfig,
}

/// Rafs storage backend configuration information.
#[derive(Clone, Default, Deserialize)]
struct RafsConfig {
    /// Configuration for storage subsystem.
    pub device: FactoryConfig,
    /// Filesystem working mode.
    pub mode: String,
    /// Whether to validate data digest before use.
    #[serde(default)]
    pub digest_validate: bool,
    /// Io statistics.
    #[serde(default)]
    pub iostats_files: bool,
    /// Filesystem prefetching configuration.
    #[serde(default)]
    pub fs_prefetch: FsPrefetchControl,
    /// Enable extended attributes.
    #[serde(default)]
    pub enable_xattr: bool,
    /// Record filesystem access pattern.
    #[serde(default)]
    pub access_pattern: bool,
    /// Record file name if file access trace log.
    #[serde(default)]
    pub latest_read_files: bool,
    // ZERO value means, amplifying user io is not enabled.
    #[serde(default = "default_batch_size")]
    pub amplify_io: usize,
}

impl TryFrom<RafsConfig> for ConfigV2 {
    type Error = std::io::Error;

    fn try_from(v: RafsConfig) -> std::result::Result<Self, Self::Error> {
        let backend: BackendConfigV2 = (&v.device.backend).try_into()?;
        let mut cache: CacheConfigV2 = (&v.device.cache).try_into()?;
        let rafs = RafsConfigV2 {
            mode: v.mode,
            batch_size: v.amplify_io,
            validate: v.digest_validate,
            enable_xattr: v.enable_xattr,
            iostats_files: v.iostats_files,
            access_pattern: v.access_pattern,
            latest_read_files: v.latest_read_files,
            prefetch: v.fs_prefetch.into(),
        };
        if !cache.prefetch.enable && rafs.prefetch.enable {
            cache.prefetch = rafs.prefetch.clone();
        }

        Ok(ConfigV2 {
            version: 2,
            id: v.device.id,
            backend: Some(backend),
            cache: Some(cache),
            rafs: Some(rafs),
            internal: ConfigV2Internal::default(),
        })
    }
}

/// Configuration information for filesystem data prefetch.
#[derive(Clone, Default, Deserialize)]
struct FsPrefetchControl {
    /// Whether the filesystem layer data prefetch is enabled or not.
    #[serde(default)]
    pub enable: bool,

    /// How many working threads to prefetch data.
    #[serde(default = "default_prefetch_threads")]
    pub threads_count: usize,

    /// Window size in unit of bytes to merge request to backend.
    #[serde(default = "default_batch_size")]
    pub merging_size: usize,

    /// Network bandwidth limitation for prefetching.
    ///
    /// In unit of Bytes. It sets a limit to prefetch bandwidth usage in order to
    /// reduce congestion with normal user IO.
    /// bandwidth_rate == 0 -- prefetch bandwidth ratelimit disabled
    /// bandwidth_rate > 0  -- prefetch bandwidth ratelimit enabled.
    ///                        Please note that if the value is less than Rafs chunk size,
    ///                        it will be raised to the chunk size.
    #[serde(default)]
    pub bandwidth_rate: u32,

    /// Whether to prefetch all filesystem data.
    #[serde(default = "default_prefetch_all")]
    pub prefetch_all: bool,
}

impl From<FsPrefetchControl> for PrefetchConfigV2 {
    fn from(v: FsPrefetchControl) -> Self {
        PrefetchConfigV2 {
            enable: v.enable,
            threads: v.threads_count,
            batch_size: v.merging_size,
            bandwidth_limit: v.bandwidth_rate,
            prefetch_all: v.prefetch_all,
        }
    }
}

/// Configuration information for blob data prefetching.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct BlobPrefetchConfig {
    /// Whether to enable blob data prefetching.
    pub enable: bool,
    /// Number of data prefetching working threads.
    pub threads_count: usize,
    /// The maximum size of a merged IO request.
    pub merging_size: usize,
    /// Network bandwidth rate limit in unit of Bytes and Zero means no limit.
    pub bandwidth_rate: u32,
}

impl From<&BlobPrefetchConfig> for PrefetchConfigV2 {
    fn from(v: &BlobPrefetchConfig) -> Self {
        PrefetchConfigV2 {
            enable: v.enable,
            threads: v.threads_count,
            batch_size: v.merging_size,
            bandwidth_limit: v.bandwidth_rate,
            prefetch_all: true,
        }
    }
}

/// Configuration information for a cached blob, corresponding to `FactoryConfig`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct BlobCacheEntryConfig {
    /// Identifier for the blob cache configuration: corresponding to `FactoryConfig::id`.
    #[serde(default)]
    id: String,
    /// Type of storage backend, corresponding to `FactoryConfig::BackendConfig::backend_type`.
    backend_type: String,
    /// Configuration for storage backend, corresponding to `FactoryConfig::BackendConfig::backend_config`.
    ///
    /// Possible value: `LocalFsConfig`, `RegistryConfig`, `OssConfig`, `LocalDiskConfig`.
    backend_config: Value,
    /// Type of blob cache, corresponding to `FactoryConfig::CacheConfig::cache_type`.
    ///
    /// Possible value: "fscache", "filecache".
    cache_type: String,
    /// Configuration for blob cache, corresponding to `FactoryConfig::CacheConfig::cache_config`.
    ///
    /// Possible value: `FileCacheConfig`, `FsCacheConfig`.
    cache_config: Value,
    /// Configuration for data prefetch.
    #[serde(default)]
    prefetch_config: BlobPrefetchConfig,
    /// Optional file path for metadata blobs.
    #[serde(default)]
    metadata_path: Option<String>,
}

impl TryFrom<&BlobCacheEntryConfig> for BlobCacheEntryConfigV2 {
    type Error = std::io::Error;

    fn try_from(v: &BlobCacheEntryConfig) -> std::result::Result<Self, Self::Error> {
        let backend_config = BackendConfig {
            backend_type: v.backend_type.clone(),
            backend_config: v.backend_config.clone(),
        };
        let cache_config = CacheConfig {
            cache_type: v.cache_type.clone(),
            cache_compressed: false,
            cache_config: v.cache_config.clone(),
            cache_validate: false,
            prefetch_config: v.prefetch_config.clone(),
        };
        Ok(BlobCacheEntryConfigV2 {
            version: 2,
            id: v.id.clone(),
            backend: (&backend_config).try_into()?,
            cache: (&cache_config).try_into()?,
            metadata_path: v.metadata_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobCacheEntry, BLOB_CACHE_TYPE_META_BLOB};

    #[test]
    fn test_blob_prefetch_config() {
        let config = BlobPrefetchConfig::default();
        assert!(!config.enable);
        assert_eq!(config.threads_count, 0);
        assert_eq!(config.merging_size, 0);
        assert_eq!(config.bandwidth_rate, 0);

        let content = r#"{
            "enable": true,
            "threads_count": 2,
            "merging_size": 4,
            "bandwidth_rate": 5
        }"#;
        let config: BlobPrefetchConfig = serde_json::from_str(content).unwrap();
        assert!(config.enable);
        assert_eq!(config.threads_count, 2);
        assert_eq!(config.merging_size, 4);
        assert_eq!(config.bandwidth_rate, 5);

        let config: PrefetchConfigV2 = (&config).into();
        assert!(config.enable);
        assert_eq!(config.threads, 2);
        assert_eq!(config.batch_size, 4);
        assert_eq!(config.bandwidth_limit, 5);
        assert!(config.prefetch_all);
    }

    #[test]
    fn test_file_cache_config() {
        let config: FileCacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(&config.work_dir, ".");
        assert!(!config.disable_indexed_map);

        let config: FileCacheConfig =
            serde_json::from_str("{\"work_dir\":\"/tmp\",\"disable_indexed_map\":true}").unwrap();
        assert_eq!(&config.work_dir, "/tmp");
        assert!(config.get_work_dir().is_ok());
        assert!(config.disable_indexed_map);

        let config: FileCacheConfig =
            serde_json::from_str("{\"work_dir\":\"/proc/mounts\",\"disable_indexed_map\":true}")
                .unwrap();
        assert!(config.get_work_dir().is_err());
    }

    #[test]
    fn test_fs_cache_config() {
        let config: FsCacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(&config.work_dir, ".");

        let config: FileCacheConfig = serde_json::from_str("{\"work_dir\":\"/tmp\"}").unwrap();
        assert_eq!(&config.work_dir, "/tmp");
        assert!(config.get_work_dir().is_ok());

        let config: FileCacheConfig =
            serde_json::from_str("{\"work_dir\":\"/proc/mounts\"}").unwrap();
        assert!(config.get_work_dir().is_err());
    }

    #[test]
    fn test_blob_cache_entry() {
        let content = r#"{
            "type": "bootstrap",
            "id": "blob1",
            "config": {
                "id": "cache1",
                "backend_type": "localfs",
                "backend_config": {},
                "cache_type": "fscache",
                "cache_config": {},
                "prefetch_config": {
                    "enable": true,
                    "threads_count": 2,
                    "merging_size": 4,
                    "bandwidth_rate": 5
                },
                "metadata_path": "/tmp/metadata1"
            },
            "domain_id": "domain1"
        }"#;
        let config: BlobCacheEntry = serde_json::from_str(content).unwrap();
        assert_eq!(&config.blob_type, BLOB_CACHE_TYPE_META_BLOB);
        assert_eq!(&config.blob_id, "blob1");
        assert_eq!(&config.domain_id, "domain1");

        let blob_config = config.blob_config_legacy.as_ref().unwrap();
        assert_eq!(blob_config.id, "cache1");
        assert_eq!(blob_config.backend_type, "localfs");
        assert_eq!(blob_config.cache_type, "fscache");
        assert!(blob_config.cache_config.is_object());
        assert!(blob_config.prefetch_config.enable);
        assert_eq!(blob_config.prefetch_config.threads_count, 2);
        assert_eq!(blob_config.prefetch_config.merging_size, 4);
        assert_eq!(
            blob_config.metadata_path.as_ref().unwrap().as_str(),
            "/tmp/metadata1"
        );

        let blob_config: BlobCacheEntryConfigV2 = blob_config.try_into().unwrap();
        assert_eq!(blob_config.id, "cache1");
        assert_eq!(blob_config.backend.backend_type, "localfs");
        assert_eq!(blob_config.cache.cache_type, "fscache");
        assert!(blob_config.cache.fs_cache.is_some());
        assert!(blob_config.cache.prefetch.enable);
        assert_eq!(blob_config.cache.prefetch.threads, 2);
        assert_eq!(blob_config.cache.prefetch.batch_size, 4);
        assert_eq!(
            blob_config.metadata_path.as_ref().unwrap().as_str(),
            "/tmp/metadata1"
        );

        let content = r#"{
            "type": "bootstrap",
            "id": "blob1",
            "config": {
                "id": "cache1",
                "backend_type": "localfs",
                "backend_config": {},
                "cache_type": "fscache",
                "cache_config": {},
                "metadata_path": "/tmp/metadata1"
            },
            "domain_id": "domain1"
        }"#;
        let config: BlobCacheEntry = serde_json::from_str(content).unwrap();
        let blob_config = config.blob_config_legacy.as_ref().unwrap();
        assert!(!blob_config.prefetch_config.enable);
        assert_eq!(blob_config.prefetch_config.threads_count, 0);
        assert_eq!(blob_config.prefetch_config.merging_size, 0);
    }

    #[test]
    fn test_proxy_config() {
        let content = r#"{
            "url": "foo.com",
            "ping_url": "ping.foo.com",
            "fallback": true
        }"#;
        let config: ProxyConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.url, "foo.com");
        assert_eq!(config.ping_url, "ping.foo.com");
        assert!(config.fallback);
        assert_eq!(config.check_interval, 5);
    }

    #[test]
    fn test_oss_config() {
        let content = r#"{
            "endpoint": "test",
            "access_key_id": "test",
            "access_key_secret": "test",
            "bucket_name": "antsys-nydus",
            "object_prefix":"nydus_v2/"
        }"#;
        let config: OssConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.scheme, "https");
        assert!(!config.skip_verify);
        assert_eq!(config.timeout, 5);
        assert_eq!(config.connect_timeout, 5);
    }

    #[test]
    fn test_s3_config() {
        let content = r#"{
            "endpoint": "test",
            "region": "us-east-1",
            "access_key_id": "test",
            "access_key_secret": "test",
            "bucket_name": "antsys-nydus",
            "object_prefix":"nydus_v2/"
        }"#;
        let config: OssConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.scheme, "https");
        assert!(!config.skip_verify);
        assert_eq!(config.timeout, 5);
        assert_eq!(config.connect_timeout, 5);
    }

    #[test]
    fn test_registry_config() {
        let content = r#"{
	    "scheme": "http",
            "skip_verify": true,
	    "host": "my-registry:5000",
	    "repo": "test/repo",
	    "auth": "base64_encoded_auth",
	    "registry_token": "bearer_token",
	    "blob_redirected_host": "blob_redirected_host"
        }"#;
        let config: RegistryConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.scheme, "http");
        assert!(config.skip_verify);
    }

    #[test]
    fn test_localfs_config() {
        let content = r#"{
            "blob_file": "blob_file",
            "dir": "blob_dir",
            "alt_dirs": ["dir1", "dir2"]
        }"#;
        let config: LocalFsConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.blob_file, "blob_file");
        assert_eq!(config.dir, "blob_dir");
        assert_eq!(config.alt_dirs, vec!["dir1", "dir2"]);
    }

    #[test]
    fn test_localdisk_config() {
        let content = r#"{
            "device_path": "device_path"
        }"#;
        let config: LocalDiskConfig = serde_json::from_str(content).unwrap();
        assert_eq!(config.device_path, "device_path");
    }

    #[test]
    fn test_backend_config() {
        let config = BackendConfig {
            backend_type: "localfs".to_string(),
            backend_config: Default::default(),
        };
        let str_val = serde_json::to_string(&config).unwrap();
        let config2 = serde_json::from_str(&str_val).unwrap();

        assert_eq!(config, config2);
    }

    #[test]
    fn test_v2_version() {
        let content = "version=2";
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_none());
    }

    #[test]
    fn test_v2_backend() {
        let content = r#"version=2
        [backend]
        type = "localfs"
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_some());
        assert!(config.cache.is_none());

        let backend = config.backend.as_ref().unwrap();
        assert_eq!(&backend.backend_type, "localfs");
        assert!(backend.localfs.is_none());
        assert!(backend.oss.is_none());
        assert!(backend.registry.is_none());
    }

    #[test]
    fn test_v2_backend_localfs() {
        let content = r#"version=2
        [backend]
        type = "localfs"
        [backend.localfs]
        blob_file = "/tmp/nydus.blob.data"
        dir = "/tmp"
        alt_dirs = ["/var/nydus/cache"]
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_some());

        let backend = config.backend.as_ref().unwrap();
        assert_eq!(&backend.backend_type, "localfs");
        assert!(backend.localfs.is_some());

        let localfs = backend.localfs.as_ref().unwrap();
        assert_eq!(&localfs.blob_file, "/tmp/nydus.blob.data");
        assert_eq!(&localfs.dir, "/tmp");
        assert_eq!(&localfs.alt_dirs[0], "/var/nydus/cache");
    }

    #[test]
    fn test_v2_backend_oss() {
        let content = r#"version=2
        [backend]
        type = "oss"
        [backend.oss]
        endpoint = "my_endpoint"
        bucket_name = "my_bucket_name"
        object_prefix = "my_object_prefix"
        access_key_id = "my_access_key_id"
        access_key_secret = "my_access_key_secret"
        scheme = "http"
        skip_verify = true
        timeout = 10
        connect_timeout = 10
        retry_limit = 5
        [backend.oss.proxy]
        url = "localhost:6789"
        ping_url = "localhost:6789/ping"
        fallback = true
        check_interval = 10
        use_http = true
        [[backend.oss.mirrors]]
        host = "http://127.0.0.1:65001"
        ping_url = "http://127.0.0.1:65001/ping"
        health_check_interval = 10
        failure_limit = 10
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_some());
        assert!(config.rafs.is_none());

        let backend = config.backend.as_ref().unwrap();
        assert_eq!(&backend.backend_type, "oss");
        assert!(backend.oss.is_some());

        let oss = backend.oss.as_ref().unwrap();
        assert_eq!(&oss.endpoint, "my_endpoint");
        assert_eq!(&oss.bucket_name, "my_bucket_name");
        assert_eq!(&oss.object_prefix, "my_object_prefix");
        assert_eq!(&oss.access_key_id, "my_access_key_id");
        assert_eq!(&oss.access_key_secret, "my_access_key_secret");
        assert_eq!(&oss.scheme, "http");
        assert!(oss.skip_verify);
        assert_eq!(oss.timeout, 10);
        assert_eq!(oss.connect_timeout, 10);
        assert_eq!(oss.retry_limit, 5);
        assert_eq!(&oss.proxy.url, "localhost:6789");
        assert_eq!(&oss.proxy.ping_url, "localhost:6789/ping");
        assert_eq!(oss.proxy.check_interval, 10);
        assert!(oss.proxy.fallback);
        assert!(oss.proxy.use_http);

        assert_eq!(oss.mirrors.len(), 1);
        let mirror = &oss.mirrors[0];
        assert_eq!(mirror.host, "http://127.0.0.1:65001");
        assert_eq!(mirror.ping_url, "http://127.0.0.1:65001/ping");
        assert!(mirror.headers.is_empty());
        assert_eq!(mirror.health_check_interval, 10);
        assert_eq!(mirror.failure_limit, 10);
    }

    #[test]
    fn test_v2_backend_registry() {
        let content = r#"version=2
        [backend]
        type = "registry"
        [backend.registry]
        scheme = "http"
        host = "localhost"
        repo = "nydus"
        auth = "auth"
        skip_verify = true
        timeout = 10
        connect_timeout = 10
        retry_limit = 5
        registry_token = "bear_token"
        blob_url_scheme = "https"
        blob_redirected_host = "redirect.registry.com"
        [backend.registry.proxy]
        url = "localhost:6789"
        ping_url = "localhost:6789/ping"
        fallback = true
        check_interval = 10
        use_http = true
        [[backend.registry.mirrors]]
        host = "http://127.0.0.1:65001"
        ping_url = "http://127.0.0.1:65001/ping"
        health_check_interval = 10
        failure_limit = 10
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_some());
        assert!(config.rafs.is_none());

        let backend = config.backend.as_ref().unwrap();
        assert_eq!(&backend.backend_type, "registry");
        assert!(backend.registry.is_some());

        let registry = backend.registry.as_ref().unwrap();
        assert_eq!(&registry.scheme, "http");
        assert_eq!(&registry.host, "localhost");
        assert_eq!(&registry.repo, "nydus");
        assert_eq!(registry.auth.as_ref().unwrap(), "auth");
        assert!(registry.skip_verify);
        assert_eq!(registry.timeout, 10);
        assert_eq!(registry.connect_timeout, 10);
        assert_eq!(registry.retry_limit, 5);
        assert_eq!(registry.registry_token.as_ref().unwrap(), "bear_token");
        assert_eq!(registry.blob_url_scheme, "https");
        assert_eq!(registry.blob_redirected_host, "redirect.registry.com");

        assert_eq!(&registry.proxy.url, "localhost:6789");
        assert_eq!(&registry.proxy.ping_url, "localhost:6789/ping");
        assert_eq!(registry.proxy.check_interval, 10);
        assert!(registry.proxy.fallback);
        assert!(registry.proxy.use_http);

        assert_eq!(registry.mirrors.len(), 1);
        let mirror = &registry.mirrors[0];
        assert_eq!(mirror.host, "http://127.0.0.1:65001");
        assert_eq!(mirror.ping_url, "http://127.0.0.1:65001/ping");
        assert!(mirror.headers.is_empty());
        assert_eq!(mirror.health_check_interval, 10);
        assert_eq!(mirror.failure_limit, 10);
    }

    #[test]
    fn test_v2_cache() {
        let content = r#"version=2
        [cache]
        type = "filecache"
        compressed = true
        validate = true
        [cache.filecache]
        work_dir = "/tmp"
        [cache.fscache]
        work_dir = "./"
        [cache.prefetch]
        enable = true
        threads = 8
        batch_size = 1000000
        bandwidth_limit = 10000000
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_none());
        assert!(config.rafs.is_none());
        assert!(config.cache.is_some());

        let cache = config.cache.as_ref().unwrap();
        assert_eq!(&cache.cache_type, "filecache");
        assert!(cache.cache_compressed);
        assert!(cache.cache_validate);
        let filecache = cache.file_cache.as_ref().unwrap();
        assert_eq!(&filecache.work_dir, "/tmp");
        let fscache = cache.fs_cache.as_ref().unwrap();
        assert_eq!(&fscache.work_dir, "./");

        let prefetch = &cache.prefetch;
        assert!(prefetch.enable);
        assert_eq!(prefetch.threads, 8);
        assert_eq!(prefetch.batch_size, 1000000);
        assert_eq!(prefetch.bandwidth_limit, 10000000);
    }

    #[test]
    fn test_v2_rafs() {
        let content = r#"version=2
        [rafs]
        mode = "direct"
        batch_size = 1000000
        validate = true
        enable_xattr = true
        iostats_files = true
        access_pattern = true
        latest_read_files = true
        [rafs.prefetch]
        enable = true
        threads = 4
        batch_size = 1000000
        bandwidth_limit = 10000000
        prefetch_all = true
        "#;
        let config: ConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert!(config.backend.is_none());
        assert!(config.cache.is_none());
        assert!(config.rafs.is_some());

        let rafs = config.rafs.as_ref().unwrap();
        assert_eq!(&rafs.mode, "direct");
        assert_eq!(rafs.batch_size, 1000000);
        assert!(rafs.validate);
        assert!(rafs.enable_xattr);
        assert!(rafs.iostats_files);
        assert!(rafs.access_pattern);
        assert!(rafs.latest_read_files);
        assert!(rafs.prefetch.enable);
        assert_eq!(rafs.prefetch.threads, 4);
        assert_eq!(rafs.prefetch.batch_size, 1000000);
        assert_eq!(rafs.prefetch.bandwidth_limit, 10000000);
        assert!(rafs.prefetch.prefetch_all)
    }

    #[test]
    fn test_v2_blob_cache_entry() {
        let content = r#"version=2
        id = "my_id"
        metadata_path = "meta_path"
        [backend]
        type = "localfs"
        [backend.localfs]
        blob_file = "/tmp/nydus.blob.data"
        dir = "/tmp"
        alt_dirs = ["/var/nydus/cache"]
        [cache]
        type = "filecache"
        compressed = true
        validate = true
        [cache.filecache]
        work_dir = "/tmp"
        "#;
        let config: BlobCacheEntryConfigV2 = toml::from_str(content).unwrap();
        assert_eq!(config.version, 2);
        assert_eq!(&config.id, "my_id");
        assert_eq!(config.metadata_path.as_ref().unwrap(), "meta_path");

        let backend = &config.backend;
        assert_eq!(&backend.backend_type, "localfs");
        assert!(backend.localfs.is_some());

        let localfs = backend.localfs.as_ref().unwrap();
        assert_eq!(&localfs.blob_file, "/tmp/nydus.blob.data");
        assert_eq!(&localfs.dir, "/tmp");
        assert_eq!(&localfs.alt_dirs[0], "/var/nydus/cache");
    }

    #[test]
    fn test_sample_config_file() {
        let content = r#"{
            "device": {
                "backend": {
                    "type": "localfs",
                    "config": {
                        "dir": "/tmp/AM7TxD/blobs",
                        "readahead": true
                    }
                },
                "cache": {
                    "type": "blobcache",
                    "compressed": true,
                    "config": {
                        "work_dir": "/tmp/AM7TxD/cache"
                    }
                }
            },
            "mode": "cached",
            "digest_validate": true,
            "iostats_files": false
        }
        "#;
        let config = ConfigV2::from_str(content).unwrap();
        assert_eq!(&config.id, "");
    }

    #[test]
    fn test_snapshotter_sample_config() {
        let content = r#"
        {
            "device": {
                "backend": {
                    "type": "registry",
                    "config": {
                        "readahead": false,
                        "host": "localhost",
                        "repo": "vke/golang",
                        "auth": "",
                        "scheme": "https",
                        "proxy": {
                            "fallback": false
                        },
                        "timeout": 5,
                        "connect_timeout": 5,
                        "retry_limit": 2
                    }
                },
                "cache": {
                    "type": "blobcache",
                    "compressed": true,
                    "config": {
                        "work_dir": "/var/lib/containerd-nydus/cache",
                        "disable_indexed_map": false
                    }
                }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": true,
            "fs_prefetch": {
                "enable": true,
                "prefetch_all": true,
                "threads_count": 8,
                "merging_size": 1048576,
                "bandwidth_rate": 0
            }
        }
        "#;
        let config = ConfigV2::from_str(content).unwrap();
        assert_eq!(&config.id, "");
    }

    #[test]
    fn test_backend_http_proxy_config() {
        let config =
            r#"{"version":2,"backend":{"type":"http-proxy","http-proxy":{"addr":"/tmp"}}}"#;
        let config = ConfigV2::from_str(config).unwrap();
        let backend = config.backend.unwrap();
        assert_eq!(&backend.backend_type, "http-proxy");
        assert_eq!(&backend.http_proxy.unwrap().addr, "/tmp");
    }

    #[test]
    fn test_new_localfs() {
        let config = ConfigV2::new_localfs("id1", "./").unwrap();
        assert_eq!(&config.id, "id1");
        assert_eq!(config.backend.as_ref().unwrap().backend_type, "localfs");
    }

    #[test]
    fn test_update_registry_auth_info() {
        let config = r#"
        {
            "device": {
              "id": "test",
              "backend": {
                "type": "registry",
                "config": {
                    "readahead": false,
                    "host": "docker.io",
                    "repo": "library/nginx",
                    "scheme": "https",
                    "proxy": {
                        "fallback": false
                    },
                    "timeout": 5,
                    "connect_timeout": 5,
                    "retry_limit": 8
                }
              }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": true,
            "fs_prefetch": {
              "enable": true,
              "threads_count": 10,
              "merging_size": 131072,
              "bandwidth_rate": 10485760
            }
          }"#;

        let mut rafs_config = ConfigV2::from_str(&config).unwrap();
        let test_auth = "test_auth".to_string();

        rafs_config.update_registry_auth_info(&Some(test_auth.clone()));

        let backend = rafs_config.backend.unwrap();
        let registry = backend.registry.unwrap();
        let auth = registry.auth.unwrap();
        assert_eq!(auth, test_auth);
    }
}
