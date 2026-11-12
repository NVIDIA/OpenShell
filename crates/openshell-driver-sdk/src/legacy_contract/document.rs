// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The contract documents as protobuf JSON files.
//!
//! A driver that writes the new format writes it beside the legacy file, in a
//! file named like the legacy one with `.pb.json` in place of `.json`
//! (`bootstrap.json` and `bootstrap.pb.json`). A reader looks for the new file
//! first and falls back to the legacy one, so an old driver, which writes only
//! the legacy file, keeps working, and an old reader, which looks only for the
//! legacy file, ignores the new one.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::boundary::{BoundaryConfig, SandboxRuntimeDescriptor};
use super::convert::ContractConversionError;
use crate::proto::sandbox_runtime::v1 as pb;

/// Why a document could not be read or decoded. The text never quotes field
/// values, which include credentials, except where the underlying JSON decoder
/// does.
#[derive(Debug, thiserror::Error)]
pub enum ContractDocumentError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("decode {path}: {message}")]
    Decode { path: PathBuf, message: String },
    #[error("{0}")]
    Invalid(#[from] ContractConversionError),
}

fn pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(crate::proto::FILE_DESCRIPTOR_SET)
            .expect("the embedded descriptor set decodes")
    })
}

/// The name of the protobuf JSON file that sits beside the legacy file named
/// `legacy`: `.pb.json` in place of `.json`, or appended when the name has no
/// `.json` ending.
#[must_use]
pub fn protobuf_json_file_name(legacy: &str) -> String {
    legacy.strip_suffix(".json").map_or_else(
        || format!("{legacy}.pb.json"),
        |stem| format!("{stem}.pb.json"),
    )
}

/// The path of the protobuf JSON file that sits beside `legacy`.
#[must_use]
pub fn protobuf_json_path(legacy: &Path) -> PathBuf {
    let name = legacy
        .file_name()
        .map(|name| protobuf_json_file_name(&name.to_string_lossy()))
        .unwrap_or_default();
    legacy.with_file_name(name)
}

/// One file of a document: its name and its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFile {
    pub name: String,
    pub contents: Vec<u8>,
}

/// Both files of one document, encoded from the same value so they cannot
/// disagree. A driver writes both, by whatever means it uses to deliver files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFiles {
    /// The legacy JSON file.
    pub legacy: DocumentFile,
    /// The protobuf JSON file beside it.
    pub protobuf: DocumentFile,
}

impl DocumentFiles {
    /// Both files, legacy first.
    pub fn iter(&self) -> impl Iterator<Item = &DocumentFile> {
        [&self.legacy, &self.protobuf].into_iter()
    }
}

fn encode<M: prost::Message>(
    message_name: &str,
    message: &M,
) -> Result<Vec<u8>, ContractConversionError> {
    let descriptor = pool()
        .get_message_by_name(message_name)
        .ok_or_else(|| ContractConversionError::new("the message is not in the descriptor set"))?;
    let dynamic = DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice())
        .map_err(|_| ContractConversionError::new("the message does not match its descriptor"))?;
    // A `DynamicMessage` holds map fields in a `HashMap`, so it writes the same
    // value with its map keys in a different order each time. Sort every object
    // so a document's bytes depend only on its value.
    let value = serde_json::to_value(&dynamic)
        .map_err(|_| ContractConversionError::new("the message cannot be written as JSON"))?;
    serde_json::to_vec(&sorted_keys(value))
        .map_err(|_| ContractConversionError::new("the message cannot be written as JSON"))
}

fn sorted_keys(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sorted_keys(value)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted_keys).collect()),
        other => other,
    }
}

fn decode<M: prost::Message + Default>(
    message_name: &str,
    bytes: &[u8],
) -> Result<M, ContractConversionError> {
    let descriptor = pool()
        .get_message_by_name(message_name)
        .ok_or_else(|| ContractConversionError::new("the message is not in the descriptor set"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let dynamic = DynamicMessage::deserialize_with_options(
        descriptor,
        &mut deserializer,
        // Unknown fields are never ignored: a reader that skipped a field it
        // does not understand would skip a claim.
        &DeserializeOptions::new().deny_unknown_fields(true),
    )
    .map_err(|error| ContractConversionError::new(format!("not a valid document: {error}")))?;
    deserializer
        .end()
        .map_err(|_| ContractConversionError::new("unexpected data after the document"))?;
    dynamic
        .transcode_to::<M>()
        .map_err(|_| ContractConversionError::new("the document does not match its message"))
}

/// A contract document that has a legacy JSON form and a protobuf JSON form.
pub trait ContractDocument: Sized + Serialize + DeserializeOwned {
    /// Encode this document as protobuf JSON.
    fn to_protobuf_json(&self) -> Result<Vec<u8>, ContractConversionError>;

    /// Decode a document from protobuf JSON and validate it.
    fn from_protobuf_json(bytes: &[u8]) -> Result<Self, ContractConversionError>;

    /// Encode this document as the legacy JSON that drivers write today.
    fn to_legacy_json(&self) -> Result<Vec<u8>, ContractConversionError> {
        serde_json::to_vec(self)
            .map_err(|_| ContractConversionError::new("the document cannot be written as JSON"))
    }

    /// Encode this document in both forms. `legacy_name` is the name of the
    /// legacy file, such as `bootstrap.json`; the protobuf JSON file's name
    /// follows from it.
    fn to_files(&self, legacy_name: &str) -> Result<DocumentFiles, ContractConversionError> {
        Ok(DocumentFiles {
            legacy: DocumentFile {
                name: legacy_name.to_string(),
                contents: self.to_legacy_json()?,
            },
            protobuf: DocumentFile {
                name: protobuf_json_file_name(legacy_name),
                contents: self.to_protobuf_json()?,
            },
        })
    }
}

macro_rules! contract_document {
    ($legacy:ty, $message:ty, $name:literal) => {
        impl ContractDocument for $legacy {
            fn to_protobuf_json(&self) -> Result<Vec<u8>, ContractConversionError> {
                encode($name, &<$message>::from(self))
            }

            fn from_protobuf_json(bytes: &[u8]) -> Result<Self, ContractConversionError> {
                <$legacy>::try_from(decode::<$message>($name, bytes)?)
            }
        }
    };
}

contract_document!(
    BoundaryConfig,
    pb::BoundaryConfig,
    "openshell.sandbox.runtime.v1.BoundaryConfig"
);
contract_document!(
    SandboxRuntimeDescriptor,
    pb::SandboxRuntimeDescriptor,
    "openshell.sandbox.runtime.v1.SandboxRuntimeDescriptor"
);

/// Read the document whose legacy file is `legacy`, preferring the protobuf JSON
/// file beside it.
pub fn read_document<T: ContractDocument>(legacy: &Path) -> Result<T, ContractDocumentError> {
    let preferred = protobuf_json_path(legacy);
    match std::fs::read(&preferred) {
        Ok(bytes) => return Ok(T::from_protobuf_json(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ContractDocumentError::Io {
                path: preferred,
                source,
            });
        }
    }
    let bytes = std::fs::read(legacy).map_err(|source| ContractDocumentError::Io {
        path: legacy.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| ContractDocumentError::Decode {
        path: legacy.to_path_buf(),
        message: error.to_string(),
    })
}

/// The descriptor payload an isolation backend is given, read from the file
/// `legacy`.
///
/// For the built-in runtime a protobuf JSON descriptor beside the legacy file is
/// preferred and re-encoded as the legacy payload, which the rest of the launch
/// still uses; an invalid protobuf JSON descriptor is an error, not a fallback.
/// The payload of any other backend is opaque and is read as it is.
pub fn read_descriptor_payload(
    legacy: &Path,
    backend_name: &str,
) -> Result<Vec<u8>, ContractDocumentError> {
    if backend_name == super::BUILTIN_BACKEND_NAME {
        let preferred = protobuf_json_path(legacy);
        match std::fs::read(&preferred) {
            Ok(bytes) => {
                return SandboxRuntimeDescriptor::from_protobuf_json(&bytes)
                    .and_then(|descriptor| descriptor.to_legacy_json())
                    .map_err(|error| ContractDocumentError::Decode {
                        path: preferred,
                        message: error.to_string(),
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ContractDocumentError::Io {
                    path: preferred,
                    source,
                });
            }
        }
    }
    std::fs::read(legacy).map_err(|source| ContractDocumentError::Io {
        path: legacy.to_path_buf(),
        source,
    })
}
