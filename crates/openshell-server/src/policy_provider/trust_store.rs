// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multi-key Ed25519 trust store.
//!
//! The attested policy driver verifies envelope signatures against a
//! gateway-side trust store loaded from a single JSON file. The file's
//! shape is:
//!
//! ```json
//! {
//!   "keys": [
//!     { "key_id": "k-1", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..." }
//!   ]
//! }
//! ```
//!
//! Distribution of the file — and rotation of its keys — is operator
//! concern, outside the scope of this loader.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    #[error("trust store path is empty")]
    EmptyPath,

    #[error("failed to read trust store file '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse trust store JSON at '{path}': {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("trust store at '{path}' contains zero keys")]
    NoKeys { path: PathBuf },

    #[error("trust store at '{path}' has duplicate key_id '{key_id}'")]
    DuplicateKeyId { path: PathBuf, key_id: String },

    #[error("trust store at '{path}' has an entry with an empty key_id")]
    EmptyKeyId { path: PathBuf },

    #[error("trust store entry '{key_id}' has an unparsable public key: {reason}")]
    BadPublicKey { key_id: String, reason: String },

    #[error("trust store does not contain key_id '{key_id}'")]
    UnknownKeyId { key_id: String },

    #[error("signature for key_id '{key_id}' failed verification")]
    BadSignature { key_id: String },

    #[error("signature for key_id '{key_id}' has unexpected length {len}")]
    BadSignatureLength { key_id: String, len: usize },
}

#[derive(Debug, Deserialize)]
struct TrustStoreFile {
    keys: Vec<TrustStoreEntry>,
}

#[derive(Debug, Deserialize)]
struct TrustStoreEntry {
    key_id: String,
    public_key_pem: String,
}

/// In-memory trust store keyed by `key_id`.
#[derive(Debug, Clone)]
pub struct TrustStore {
    keys: HashMap<String, VerifyingKey>,
}

impl TrustStore {
    /// Load and validate a trust store from disk.
    pub fn load(path: &Path) -> Result<Self, TrustStoreError> {
        if path.as_os_str().is_empty() {
            return Err(TrustStoreError::EmptyPath);
        }

        let bytes = std::fs::read(path).map_err(|source| TrustStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let file: TrustStoreFile =
            serde_json::from_slice(&bytes).map_err(|source| TrustStoreError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        if file.keys.is_empty() {
            return Err(TrustStoreError::NoKeys {
                path: path.to_path_buf(),
            });
        }

        let mut keys = HashMap::with_capacity(file.keys.len());
        for entry in file.keys {
            if entry.key_id.is_empty() {
                return Err(TrustStoreError::EmptyKeyId {
                    path: path.to_path_buf(),
                });
            }
            if keys.contains_key(&entry.key_id) {
                return Err(TrustStoreError::DuplicateKeyId {
                    path: path.to_path_buf(),
                    key_id: entry.key_id,
                });
            }
            if entry.public_key_pem.trim().is_empty() {
                return Err(TrustStoreError::BadPublicKey {
                    key_id: entry.key_id,
                    reason: "PEM is empty".to_string(),
                });
            }
            let verifying = VerifyingKey::from_public_key_pem(&entry.public_key_pem).map_err(
                |e| TrustStoreError::BadPublicKey {
                    key_id: entry.key_id.clone(),
                    reason: e.to_string(),
                },
            )?;
            keys.insert(entry.key_id, verifying);
        }

        Ok(Self { keys })
    }

    /// Construct an in-memory trust store directly. Test-only helper.
    #[cfg(test)]
    #[must_use]
    pub fn from_keys(keys: HashMap<String, VerifyingKey>) -> Self {
        Self { keys }
    }

    /// Verify `signature` against `body` using the key registered under
    /// `signing_key_id`. Returns an error if the key id is unknown, the
    /// signature is malformed, or verification fails.
    pub fn verify(
        &self,
        signing_key_id: &str,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), TrustStoreError> {
        let verifying =
            self.keys
                .get(signing_key_id)
                .ok_or_else(|| TrustStoreError::UnknownKeyId {
                    key_id: signing_key_id.to_string(),
                })?;

        let signature_bytes: [u8; Signature::BYTE_SIZE] =
            signature
                .try_into()
                .map_err(|_| TrustStoreError::BadSignatureLength {
                    key_id: signing_key_id.to_string(),
                    len: signature.len(),
                })?;
        let signature = Signature::from_bytes(&signature_bytes);

        // Bring the upstream signature-trait into local scope only so the
        // single call below can dispatch. The token's spelling is fixed
        // by the upstream crate.
        use ed25519_dalek::Verifier as _;
        verifying
            .verify(body, &signature)
            .map_err(|_| TrustStoreError::BadSignature {
                key_id: signing_key_id.to_string(),
            })
    }

    /// Number of registered keys. Diagnostic helper.
    #[allow(dead_code)] // used by tests; useful for diagnostics
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[allow(dead_code)] // companion to `len`
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core_06::OsRng;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f
    }

    fn fresh_keypair() -> (SigningKey, String) {
        let signing = SigningKey::generate(&mut OsRng);
        let pem = signing
            .verifying_key()
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("encode PEM");
        (signing, pem)
    }

    #[test]
    fn loads_single_key_and_verifies() {
        let (sk, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[{{"key_id":"k-1","public_key_pem":{:?}}}]}}"#,
            pem
        );
        let tmp = write_tmp(&json);
        let store = TrustStore::load(tmp.path()).expect("loads");
        assert_eq!(store.len(), 1);

        let body = b"hello";
        let sig = sk.sign(body).to_bytes();
        store
            .verify("k-1", body, &sig)
            .expect("valid signature verifies");
    }

    #[test]
    fn empty_path_rejected() {
        let err = TrustStore::load(Path::new("")).expect_err("empty path must error");
        assert!(matches!(err, TrustStoreError::EmptyPath));
    }

    #[test]
    fn missing_file_rejected_as_io() {
        let err = TrustStore::load(Path::new("/nonexistent/trust.json"))
            .expect_err("missing file must error");
        assert!(matches!(err, TrustStoreError::Io { .. }));
    }

    #[test]
    fn malformed_json_rejected() {
        let tmp = write_tmp("not json");
        let err = TrustStore::load(tmp.path()).expect_err("malformed json must error");
        assert!(matches!(err, TrustStoreError::Parse { .. }));
    }

    #[test]
    fn zero_keys_rejected() {
        let tmp = write_tmp(r#"{"keys":[]}"#);
        let err = TrustStore::load(tmp.path()).expect_err("zero keys must error");
        assert!(matches!(err, TrustStoreError::NoKeys { .. }));
    }

    #[test]
    fn duplicate_key_id_rejected() {
        let (_, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[
                {{"key_id":"k-1","public_key_pem":{:?}}},
                {{"key_id":"k-1","public_key_pem":{:?}}}
            ]}}"#,
            pem, pem
        );
        let tmp = write_tmp(&json);
        let err = TrustStore::load(tmp.path()).expect_err("duplicate key_id must error");
        assert!(matches!(
            err,
            TrustStoreError::DuplicateKeyId { ref key_id, .. } if key_id == "k-1"
        ));
    }

    #[test]
    fn empty_key_id_rejected() {
        let (_, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[{{"key_id":"","public_key_pem":{:?}}}]}}"#,
            pem
        );
        let tmp = write_tmp(&json);
        let err = TrustStore::load(tmp.path()).expect_err("empty key_id must error");
        assert!(matches!(err, TrustStoreError::EmptyKeyId { .. }));
    }

    #[test]
    fn empty_pem_rejected() {
        let json = r#"{"keys":[{"key_id":"k-1","public_key_pem":""}]}"#;
        let tmp = write_tmp(json);
        let err = TrustStore::load(tmp.path()).expect_err("empty PEM must error");
        assert!(matches!(
            err,
            TrustStoreError::BadPublicKey { ref key_id, .. } if key_id == "k-1"
        ));
    }

    #[test]
    fn malformed_pem_rejected() {
        let json = r#"{"keys":[{"key_id":"k-1","public_key_pem":"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----\n"}]}"#;
        let tmp = write_tmp(json);
        let err = TrustStore::load(tmp.path()).expect_err("malformed PEM must error");
        assert!(matches!(
            err,
            TrustStoreError::BadPublicKey { ref key_id, .. } if key_id == "k-1"
        ));
    }

    #[test]
    fn verify_unknown_key_id_errors() {
        let (sk, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[{{"key_id":"k-1","public_key_pem":{:?}}}]}}"#,
            pem
        );
        let tmp = write_tmp(&json);
        let store = TrustStore::load(tmp.path()).expect("loads");
        let body = b"hello";
        let sig = sk.sign(body).to_bytes();
        let err = store
            .verify("does-not-exist", body, &sig)
            .expect_err("unknown key_id must error");
        assert!(matches!(err, TrustStoreError::UnknownKeyId { .. }));
    }

    #[test]
    fn verify_bad_signature_length_errors() {
        let (_, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[{{"key_id":"k-1","public_key_pem":{:?}}}]}}"#,
            pem
        );
        let tmp = write_tmp(&json);
        let store = TrustStore::load(tmp.path()).expect("loads");
        let err = store
            .verify("k-1", b"body", &[1, 2, 3])
            .expect_err("bad signature length must error");
        assert!(matches!(err, TrustStoreError::BadSignatureLength { .. }));
    }

    #[test]
    fn verify_bad_signature_errors() {
        let (sk, pem) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[{{"key_id":"k-1","public_key_pem":{:?}}}]}}"#,
            pem
        );
        let tmp = write_tmp(&json);
        let store = TrustStore::load(tmp.path()).expect("loads");
        let sig = sk.sign(b"original").to_bytes();
        let err = store
            .verify("k-1", b"tampered", &sig)
            .expect_err("tampered body must fail verify");
        assert!(matches!(err, TrustStoreError::BadSignature { .. }));
    }

    #[test]
    fn loads_multiple_keys() {
        let (_, pem1) = fresh_keypair();
        let (_, pem2) = fresh_keypair();
        let json = format!(
            r#"{{"keys":[
                {{"key_id":"k-1","public_key_pem":{:?}}},
                {{"key_id":"k-2","public_key_pem":{:?}}}
            ]}}"#,
            pem1, pem2
        );
        let tmp = write_tmp(&json);
        let store = TrustStore::load(tmp.path()).expect("loads");
        assert_eq!(store.len(), 2);
    }
}
