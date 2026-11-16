// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use tonic::Status;

const KEY_DOMAIN: &[u8] = b"openshell-refresh-material-credential-key-v1";

/// Preserve the existing domain-separated, driver-safe storage key exactly.
/// Backend failures propagate without an alternate hashing implementation.
pub fn refresh_material_storage_key(
    credential_key: &str,
    material_key: &str,
) -> Result<String, Status> {
    let key = || {
        let mut digest = openshell_crypto::sha256_digest()?;
        digest.update(KEY_DOMAIN)?;
        digest.update(&[0])?;
        digest.update(credential_key.as_bytes())?;
        digest.update(&[0])?;
        digest.update(material_key.as_bytes())?;
        digest.finish()
    };
    let bytes = key().map_err(|_: openshell_crypto::CryptoError| {
        Status::internal("refresh material storage key derivation failed")
    })?;
    let mut result = String::from("openshell.refresh.");
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_storage_key() {
        assert_eq!(
            refresh_material_storage_key("ACCESS_TOKEN", "refresh_token").unwrap(),
            "openshell.refresh.d76bb2bff1285f22baa3315b2b38879e15caa49bb0c571d08d96b0fdd1378764"
        );
        assert_ne!(
            refresh_material_storage_key("ab", "c").unwrap(),
            refresh_material_storage_key("a", "bc").unwrap()
        );
    }
}
