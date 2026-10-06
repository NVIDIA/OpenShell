// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialization helpers for OCSF event structs.
//!
//! These macros reduce boilerplate in custom `Serialize` impls that expand
//! typed enum fields into OCSF's `_id` + label pair format.

/// Insert an OCSF enum pair (`_id` integer + label string) into a JSON map.
///
/// If the value is `Some`, inserts both `"<prefix>_id": <u8>` and `"<prefix>": "<label>"`.
/// If `None`, inserts nothing.
macro_rules! insert_enum_pair {
    ($obj:expr, $prefix:literal, $value:expr) => {
        if let Some(val) = $value {
            $obj.insert(
                concat!($prefix, "_id").to_string(),
                serde_json::Value::from(crate::enums::OcsfEnum::as_u8(val)),
            );
            $obj.insert(
                $prefix.to_string(),
                serde_json::Value::from(crate::enums::OcsfEnum::label(val)),
            );
        }
    };
}

/// Insert an OCSF enum pair with a custom label override.
///
/// Uses `custom_label` if `Some`, otherwise derives label from the enum.
macro_rules! insert_enum_pair_custom {
    ($obj:expr, $prefix:literal, $id:expr, $custom_label:expr) => {
        if let Some(val) = $id {
            $obj.insert(
                concat!($prefix, "_id").to_string(),
                serde_json::Value::from(crate::enums::OcsfEnum::as_u8(val)),
            );
            let label = $custom_label
                .as_deref()
                .unwrap_or(crate::enums::OcsfEnum::label(val));
            $obj.insert($prefix.to_string(), serde_json::Value::from(label));
        }
    };
}

/// Insert an optional field into a JSON map if present.
macro_rules! insert_optional {
    ($obj:expr, $key:literal, $value:expr) => {
        if let Some(ref val) = $value {
            $obj.insert(
                $key.to_string(),
                serde_json::to_value(val).map_err(serde::ser::Error::custom)?,
            );
        }
    };
}

/// Insert a required field into a JSON map.
macro_rules! insert_required {
    ($obj:expr, $key:literal, $value:expr) => {
        $obj.insert(
            $key.to_string(),
            serde_json::to_value(&$value).map_err(serde::ser::Error::custom)?,
        );
    };
}

pub(crate) use insert_enum_pair;
pub(crate) use insert_enum_pair_custom;
pub(crate) use insert_optional;
pub(crate) use insert_required;
