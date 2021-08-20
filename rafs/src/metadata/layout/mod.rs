// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::ffi::OsStr;
use std::io::Result;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;

pub const RAFS_SUPER_VERSION_V4: u32 = 0x400;
pub const RAFS_SUPER_VERSION_V5: u32 = 0x500;
pub const RAFS_SUPER_MIN_VERSION: u32 = RAFS_SUPER_VERSION_V4;
pub const RAFS_ROOT_INODE: u64 = 1;

pub type XattrName = Vec<u8>;
pub type XattrValue = Vec<u8>;

pub mod v5;

#[macro_export]
macro_rules! impl_bootstrap_converter {
    ($T: ty) => {
        impl TryFrom<&[u8]> for &$T {
            type Error = Error;

            fn try_from(buf: &[u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &*(ptr as *const $T) })
            }
        }

        impl TryFrom<&mut [u8]> for &mut $T {
            type Error = Error;

            fn try_from(buf: &mut [u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &mut *(ptr as *const $T as *mut $T) })
            }
        }

        impl AsRef<[u8]> for $T {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { &*std::slice::from_raw_parts(ptr, size_of::<$T>()) }
            }
        }

        impl AsMut<[u8]> for $T {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { &mut *std::slice::from_raw_parts_mut(ptr, size_of::<$T>()) }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_pub_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        #[inline]
        pub fn $G(&self) -> $U {
            <$U>::from_le(self.$F)
        }

        #[inline]
        pub fn $S(&mut self, $F: $U) {
            self.$F = <$U>::to_le($F);
        }
    };
}

/// Parse a `buf` into two utf-8 strings.
pub fn parse_string(buf: &[u8]) -> Result<(&str, &str)> {
    std::str::from_utf8(buf)
        .map(|origin| {
            if let Some(pos) = origin.find('\0') {
                origin.split_at(pos)
            } else {
                (origin, "")
            }
        })
        .map_err(|e| einval!(format!("failed in parsing string, {:?}", e)))
}

/// Convert a byte slice into OsStr.
pub fn bytes_to_os_str(buf: &[u8]) -> &OsStr {
    OsStr::from_bytes(buf)
}

/// Parse a 'buf' to xattr pair then callback.
pub fn parse_xattr<F>(data: &[u8], size: usize, mut cb: F) -> Result<()>
where
    F: FnMut(&OsStr, XattrValue) -> bool,
{
    let mut i: usize = 0;
    let mut rest_data = &data[0..size];

    while i < size {
        let (pair_size, rest) = rest_data.split_at(size_of::<u32>());
        let pair_size = u32::from_le_bytes(
            pair_size
                .try_into()
                .map_err(|_| einval!("failed to parse xattr pair size"))?,
        ) as usize;
        i += size_of::<u32>();

        let (pair, rest) = rest.split_at(pair_size);
        if let Some(pos) = pair.iter().position(|&c| c == 0) {
            let (name, value) = pair.split_at(pos);
            let name = OsStr::from_bytes(name);
            let value = value[1..].to_vec();
            if !cb(name, value) {
                break;
            }
        }
        i += pair_size;

        rest_data = rest;
    }

    Ok(())
}

/// Parse a 'buf' to xattr name list.
pub fn parse_xattr_names(data: &[u8], size: usize) -> Result<Vec<XattrName>> {
    let mut result = Vec::new();

    parse_xattr(data, size, |name, _| {
        result.push(name.as_bytes().to_vec());
        true
    })?;

    Ok(result)
}

/// Parse a 'buf' to xattr value by xattr name.
pub fn parse_xattr_value(data: &[u8], size: usize, name: &OsStr) -> Result<Option<XattrValue>> {
    let mut value = None;

    parse_xattr(data, size, |_name, _value| {
        if _name == name {
            value = Some(_value);
            // stop the iteration if we found the xattr name.
            return false;
        }
        true
    })?;

    Ok(value)
}
