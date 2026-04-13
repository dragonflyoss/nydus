// Copyright (C) 2026 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Protocol definitions for UFFD communication.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// UFFD protocol version
pub const UFFD_PROTOCOL_VERSION: u32 = 1;

/// Message type enum for UFFD protocol
#[derive(Debug, Clone, Copy, Default, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    #[default]
    Handshake = 0,
    PageFault = 1,
    Stat = 2,
    StatResp = 3,
}

/// Fault handling policy for UFFD
#[derive(Debug, Clone, Copy, Default, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// Zero-copy mode: send fd to client, let client do mmap
    #[default]
    Zerocopy = 0,
    /// Copy mode: use UFFDIO_COPY to copy data directly
    Copy = 1,
}

/// VMA region information for userfaultfd registration (JSON format)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VmaRegion {
    pub base_host_virt_addr: u64,
    pub size: usize,
    pub offset: u64,
    pub page_size: usize,
    #[serde(default)]
    pub page_size_kib: usize,
    #[serde(default = "default_prot")]
    pub prot: i32,
    #[serde(default = "default_flags")]
    pub flags: i32,
}

fn default_prot() -> i32 {
    libc::PROT_READ
}

fn default_flags() -> i32 {
    libc::MAP_PRIVATE | libc::MAP_FIXED
}

impl VmaRegion {
    /// Create a new VmaRegion with default prot and flags.
    #[allow(dead_code)]
    pub fn new(base_host_virt_addr: u64, size: usize, offset: u64, page_size: usize) -> Self {
        Self {
            base_host_virt_addr,
            size,
            offset,
            page_size,
            page_size_kib: 0,
            prot: libc::PROT_READ,
            flags: libc::MAP_PRIVATE | libc::MAP_FIXED,
        }
    }
}

/// Handshake request (Client -> Server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    #[serde(default)]
    pub r#type: MessageType,
    pub regions: Vec<VmaRegion>,
    #[serde(default)]
    pub policy: FaultPolicy,
    /// Enable pre-fault in zerocopy mode (default: false)
    #[serde(default)]
    pub enable_prefault: bool,
}

/// Page fault response (Server -> Client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageFaultResponse {
    pub r#type: MessageType,
    pub ranges: Vec<BlobRange>,
}

/// Blob range information for page fault response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRange {
    pub len: usize,
    pub blob_offset: u64,
    pub block_offset: u64,
}

/// Stat request (Client -> Server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatRequest {
    pub r#type: MessageType,
}

impl StatRequest {
    pub fn new() -> Self {
        Self {
            r#type: MessageType::Stat,
        }
    }
}

impl Default for StatRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Stat response (Server -> Client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub r#type: MessageType,
    pub size: u64,
    pub block_size: u32,
    pub flags: u32,
    pub version: u32,
}

impl StatResponse {
    pub fn new(size: u64, block_size: u32, flags: u32, version: u32) -> Self {
        Self {
            r#type: MessageType::StatResp,
            size,
            block_size,
            flags,
            version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uffd_protocol_version() {
        assert_eq!(UFFD_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_message_type_default() {
        let msg_type: MessageType = Default::default();
        assert_eq!(msg_type, MessageType::Handshake);
    }

    #[test]
    fn test_message_type_serialize() {
        let msg_type = MessageType::Handshake;
        let json = serde_json::to_string(&msg_type).unwrap();
        assert_eq!(json, "0");

        let msg_type = MessageType::PageFault;
        let json = serde_json::to_string(&msg_type).unwrap();
        assert_eq!(json, "1");

        let msg_type = MessageType::Stat;
        let json = serde_json::to_string(&msg_type).unwrap();
        assert_eq!(json, "2");

        let msg_type = MessageType::StatResp;
        let json = serde_json::to_string(&msg_type).unwrap();
        assert_eq!(json, "3");
    }

    #[test]
    fn test_message_type_deserialize() {
        let msg_type: MessageType = serde_json::from_str("0").unwrap();
        assert_eq!(msg_type, MessageType::Handshake);

        let msg_type: MessageType = serde_json::from_str("1").unwrap();
        assert_eq!(msg_type, MessageType::PageFault);

        let msg_type: MessageType = serde_json::from_str("2").unwrap();
        assert_eq!(msg_type, MessageType::Stat);

        let msg_type: MessageType = serde_json::from_str("3").unwrap();
        assert_eq!(msg_type, MessageType::StatResp);
    }

    #[test]
    fn test_fault_policy_default() {
        let policy: FaultPolicy = Default::default();
        assert_eq!(policy, FaultPolicy::Zerocopy);
    }

    #[test]
    fn test_vma_region_new() {
        let region = VmaRegion::new(0x1000, 0x2000, 0x100, 0x1000);
        assert_eq!(region.base_host_virt_addr, 0x1000);
        assert_eq!(region.size, 0x2000);
        assert_eq!(region.offset, 0x100);
        assert_eq!(region.page_size, 0x1000);
        assert_eq!(region.prot, libc::PROT_READ);
        assert_eq!(region.flags, libc::MAP_PRIVATE | libc::MAP_FIXED);
    }

    #[test]
    fn test_vma_region_serialize() {
        let region = VmaRegion {
            base_host_virt_addr: 0x1000,
            size: 0x2000,
            offset: 0x100,
            page_size: 0x1000,
            page_size_kib: 0,
            prot: libc::PROT_READ,
            flags: libc::MAP_PRIVATE | libc::MAP_FIXED,
        };

        let json = serde_json::to_string(&region).unwrap();
        let region2: VmaRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(region.base_host_virt_addr, region2.base_host_virt_addr);
        assert_eq!(region.size, region2.size);
        assert_eq!(region.offset, region2.offset);
        assert_eq!(region.page_size, region2.page_size);
    }

    #[test]
    fn test_vma_region_default_prot_flags() {
        let json = r#"{"base_host_virt_addr":4096,"size":8192,"offset":256,"page_size":4096}"#;
        let region: VmaRegion = serde_json::from_str(json).unwrap();
        assert_eq!(region.prot, libc::PROT_READ);
        assert_eq!(region.flags, libc::MAP_PRIVATE | libc::MAP_FIXED);
    }

    #[test]
    fn test_handshake_request() {
        let region = VmaRegion::new(0x1000, 0x2000, 0x100, 0x1000);

        let request = HandshakeRequest {
            r#type: MessageType::Handshake,
            regions: vec![region],
            policy: FaultPolicy::default(),
            enable_prefault: false,
        };

        let json = serde_json::to_string(&request).unwrap();
        let request2: HandshakeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request2.r#type, MessageType::Handshake);
        assert_eq!(request2.regions.len(), 1);
        assert_eq!(request2.regions[0].page_size, 0x1000);
        assert!(!request2.enable_prefault);
    }

    #[test]
    fn test_handshake_request_default_type() {
        let json = r#"{"regions":[{"base_host_virt_addr":4096,"size":8192,"offset":256,"page_size":4096}]}"#;
        let request: HandshakeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.r#type, MessageType::Handshake);
        assert_eq!(request.regions[0].page_size, 4096);
    }

    #[test]
    fn test_blob_range() {
        let range = BlobRange {
            len: 0x1000,
            blob_offset: 0x100,
            block_offset: 0x200,
        };

        let json = serde_json::to_string(&range).unwrap();
        let range2: BlobRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range.len, range2.len);
        assert_eq!(range.blob_offset, range2.blob_offset);
        assert_eq!(range.block_offset, range2.block_offset);
    }

    #[test]
    fn test_page_fault_response() {
        let response = PageFaultResponse {
            r#type: MessageType::PageFault,
            ranges: vec![BlobRange {
                len: 0x1000,
                blob_offset: 0x100,
                block_offset: 0x200,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        let response2: PageFaultResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response2.r#type, MessageType::PageFault);
        assert_eq!(response2.ranges.len(), 1);
    }

    #[test]
    fn test_stat_response() {
        let response = StatResponse::new(1024 * 1024 * 100, 4096, 0, 1);
        assert_eq!(response.r#type, MessageType::StatResp);
        assert_eq!(response.size, 1024 * 1024 * 100);
        assert_eq!(response.block_size, 4096);
        assert_eq!(response.flags, 0);
        assert_eq!(response.version, 1);

        let json = serde_json::to_string(&response).unwrap();
        let response2: StatResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response2.size, response.size);
        assert_eq!(response2.block_size, response.block_size);
    }

    #[test]
    fn test_stat_request_new() {
        let request = StatRequest::new();
        assert_eq!(request.r#type, MessageType::Stat);
    }

    #[test]
    fn test_stat_request_default() {
        let request = StatRequest::default();
        assert_eq!(request.r#type, MessageType::Stat);
    }

    #[test]
    fn test_fault_policy_serialize() {
        let policy = FaultPolicy::Zerocopy;
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "0");

        let policy = FaultPolicy::Copy;
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, "1");
    }

    #[test]
    fn test_fault_policy_deserialize() {
        let policy: FaultPolicy = serde_json::from_str("0").unwrap();
        assert_eq!(policy, FaultPolicy::Zerocopy);

        let policy: FaultPolicy = serde_json::from_str("1").unwrap();
        assert_eq!(policy, FaultPolicy::Copy);
    }
}
