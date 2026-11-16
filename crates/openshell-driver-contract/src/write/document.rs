// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::codec::{Codec, binary_file_name};
use crate::convert::ContractConversionError;

/// A document that [`encode`] can write: the runtime descriptor and the
/// boundary configuration.
pub trait Document: Codec {}

impl<T: Codec> Document for T {}

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
    /// The binary protobuf file.
    pub binary: DocumentFile,
    /// The legacy JSON file beside it. Removed with the legacy encoding.
    pub legacy: DocumentFile,
}

impl DocumentFiles {
    /// Both files, binary first.
    pub fn iter(&self) -> impl Iterator<Item = &DocumentFile> {
        [&self.binary, &self.legacy].into_iter()
    }
}

/// Encode `document` as the files that a driver writes for it.
///
/// The document is validated first, so a driver cannot write what a reader would
/// reject. The files are named after the document's type.
pub fn encode<D: Document>(document: &D) -> Result<DocumentFiles, ContractConversionError> {
    document.validate()?;
    let binary = document.to_binary();
    // The reader's decoding checks, applied before anything is written.
    D::from_binary(&binary)?;
    let legacy = serde_json::to_vec(document)
        .map_err(|_| ContractConversionError::new("the document cannot be written as JSON"))?;
    Ok(DocumentFiles {
        binary: DocumentFile {
            name: binary_file_name(D::LEGACY_FILE_NAME),
            contents: binary,
        },
        legacy: DocumentFile {
            name: D::LEGACY_FILE_NAME.to_string(),
            contents: legacy,
        },
    })
}
