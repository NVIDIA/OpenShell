// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How a document is laid out in files, and how each type becomes bytes.
//!
//! A document is written as a binary protobuf file beside a legacy JSON file.
//! The binary file is named like the legacy one with `.pb` in place of `.json`
//! (`bootstrap.json` and `bootstrap.pb`). A reader looks for the binary file
//! first and falls back to the legacy one, so an old driver, which writes only
//! the legacy file, keeps working, and an old reader, which looks only for the
//! legacy file, ignores the binary one.
//!
//! Callers do not name the files: [`crate::write::encode`] returns them with
//! their names and the `read` functions take the path of the legacy file.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::convert::ContractConversionError;
use crate::model::{BoundaryConfig, SandboxRuntimeDescriptor};
use crate::proto::sandbox_runtime::v1 as pb;

/// The name of the binary file that sits beside the legacy file `legacy`: `.pb`
/// in place of `.json`, or appended when the name has no `.json` ending.
pub fn binary_file_name(legacy: &str) -> String {
    legacy
        .strip_suffix(".json")
        .map_or_else(|| format!("{legacy}.pb"), |stem| format!("{stem}.pb"))
}

/// The path of the binary file that sits beside the legacy file `legacy`.
pub fn binary_path(legacy: &Path) -> PathBuf {
    let name = legacy
        .file_name()
        .map(|name| binary_file_name(&name.to_string_lossy()))
        .unwrap_or_default();
    legacy.with_file_name(name)
}

/// A contract document that has a legacy JSON form and a binary protobuf form.
///
/// The encoding half is used only by the `write` feature. The contract crate
/// implements it for the runtime descriptor and the boundary configuration;
/// `openshell-driver-sdk` implements it for the documents it defines.
#[cfg_attr(not(feature = "write"), allow(dead_code))]
pub trait Codec: Serialize + DeserializeOwned + Sized {
    /// The name of the legacy file a driver writes this document to.
    const LEGACY_FILE_NAME: &'static str;

    /// Reject a document that a reader would reject after decoding it.
    fn validate(&self) -> Result<(), ContractConversionError>;

    /// Encode this document as binary protobuf, without validating it.
    fn to_binary(&self) -> Vec<u8>;

    /// Decode a document from binary protobuf and validate it. Unknown fields
    /// are skipped, as protobuf readers do; a document's `contract_version` is
    /// what says whether a reader understands it.
    fn from_binary(bytes: &[u8]) -> Result<Self, ContractConversionError>;
}

fn decode<M: prost::Message + Default>(bytes: &[u8]) -> Result<M, ContractConversionError> {
    M::decode(bytes)
        .map_err(|error| ContractConversionError::new(format!("not a valid document: {error}")))
}

#[cfg_attr(not(feature = "write"), allow(dead_code))]
fn invalid(error: impl std::fmt::Display) -> ContractConversionError {
    ContractConversionError::new(error.to_string())
}

macro_rules! codec {
    ($model:ty, $message:ty, $name:literal, |$document:ident| $validate:block) => {
        impl Codec for $model {
            const LEGACY_FILE_NAME: &'static str = $name;

            fn validate(&self) -> Result<(), ContractConversionError> {
                let $document = self;
                $validate
            }

            fn to_binary(&self) -> Vec<u8> {
                prost::Message::encode_to_vec(&<$message>::from(self))
            }

            fn from_binary(bytes: &[u8]) -> Result<Self, ContractConversionError> {
                <$model>::try_from(decode::<$message>(bytes)?)
            }
        }
    };
}

codec!(
    BoundaryConfig,
    pb::BoundaryConfig,
    "boundary-bootstrap.json",
    |config| {
        config
            .provisioning_evidence
            .validate(&config.generation)
            .map_err(invalid)
    }
);
codec!(
    SandboxRuntimeDescriptor,
    pb::SandboxRuntimeDescriptor,
    "runtime-descriptor.json",
    |descriptor| {
        descriptor.transport.validate().map_err(invalid)?;
        descriptor
            .provisioning_evidence
            .validate(&descriptor.generation)
            .map_err(invalid)
    }
);
