// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable CDI name checking for non-Linux targets.

/// Check `<vendor>/<class>=<name>` syntax without resolving or authorizing devices.
/// Input is neither trimmed nor normalized.
#[must_use]
pub fn is_qualified_name(device: &str) -> bool {
    let Some((kind, name)) = device.split_once('=') else {
        return false;
    };
    let Some((vendor, class)) = kind.split_once('/') else {
        return false;
    };
    let valid_component = |value: &str, device_name: bool| {
        let bytes = value.as_bytes();
        bytes.first().is_some_and(|byte| {
            if device_name {
                byte.is_ascii_alphanumeric()
            } else {
                byte.is_ascii_alphabetic()
            }
        }) && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.')
                    || (device_name && *byte == b':')
            })
    };
    valid_component(vendor, false) && valid_component(class, false) && valid_component(name, true)
}
