// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor and sandbox-boundary side of the contract: what a reader
//! checks about a document before it acts on it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::codec::{Codec, binary_path};
use crate::convert::ContractConversionError;
use crate::model::{BUILTIN_BACKEND_NAME, BackendError, BoundaryConfig, SandboxRuntimeDescriptor};

/// Why a document could not be read or decoded. The text never quotes field
/// values, which include credentials, except where the underlying JSON decoder
/// does.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
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

/// Read the boundary configuration whose legacy file is `path`, preferring the
/// binary file beside it. The result is not validated beyond decoding; the
/// caller validates it before acting on it.
pub fn boundary_config(path: &Path) -> Result<BoundaryConfig, ReadError> {
    read_document(path)
}

/// Read the runtime descriptor whose legacy file is `path`, preferring the
/// binary file beside it.
pub fn runtime_descriptor(path: &Path) -> Result<SandboxRuntimeDescriptor, ReadError> {
    read_document(path)
}

/// Remove every form of the single-use document whose legacy file is `path`.
/// A form that is not there is not an error.
pub fn consume(path: &Path) -> Result<(), ReadError> {
    for file in [path.to_path_buf(), binary_path(path)] {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(ReadError::Io { path: file, source }),
        }
    }
    Ok(())
}

/// The descriptor payload an isolation backend is given, read from the file
/// `path`.
///
/// For the built-in runtime a binary descriptor beside the legacy file is
/// preferred and re-encoded as the legacy payload, which the rest of the launch
/// still uses; an invalid binary descriptor is an error, not a fallback. The
/// payload of any other backend is opaque and is read as it is.
///
/// Transitional: removed together with the legacy encoding, when the launch
/// carries the descriptor itself rather than a payload.
pub fn descriptor_payload(path: &Path, backend_name: &str) -> Result<Vec<u8>, ReadError> {
    if backend_name == BUILTIN_BACKEND_NAME {
        let preferred = binary_path(path);
        match std::fs::read(&preferred) {
            Ok(bytes) => {
                return SandboxRuntimeDescriptor::from_binary(&bytes)
                    .and_then(|descriptor| {
                        serde_json::to_vec(&descriptor).map_err(|_| {
                            ContractConversionError::new("the descriptor cannot be written as JSON")
                        })
                    })
                    .map_err(|error| ReadError::Decode {
                        path: preferred,
                        message: error.to_string(),
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ReadError::Io {
                    path: preferred,
                    source,
                });
            }
        }
    }
    std::fs::read(path).map_err(|source| ReadError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_document<T: Codec>(legacy: &Path) -> Result<T, ReadError> {
    let preferred = binary_path(legacy);
    match std::fs::read(&preferred) {
        Ok(bytes) => return Ok(T::from_binary(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ReadError::Io {
                path: preferred,
                source,
            });
        }
    }
    let bytes = std::fs::read(legacy).map_err(|source| ReadError::Io {
        path: legacy.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| ReadError::Decode {
        path: legacy.to_path_buf(),
        message: error.to_string(),
    })
}

/// Validate driver-specific immutable coordinates before a boundary binds them.
///
/// Claim values are opaque to the common protocol, but empty or
/// whitespace-bearing identifiers cannot safely distinguish runtime objects.
pub fn validate_resource_claims(claims: &BTreeMap<String, String>) -> Result<(), BackendError> {
    for (key, value) in claims {
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(
                "boundary resource-claim keys must be non-empty and contain no whitespace"
                    .to_string(),
            ));
        }
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(BackendError::Descriptor(format!(
                "boundary resource claim {key:?} must be non-empty and contain no whitespace"
            )));
        }
    }
    Ok(())
}
