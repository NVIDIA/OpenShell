// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Load and validate sandbox launch signing before gateway startup connects drivers.

use std::sync::Arc;

use ryno_core::{Error, GatewayJwtConfig};

use super::sandbox_jwt::{ExtensionJwtIssuer, SandboxSessionJwtAuthority};

pub struct LaunchSigningAuthorities {
    pub extension: Arc<ExtensionJwtIssuer>,
    pub sandbox_session: Arc<SandboxSessionJwtAuthority>,
}

pub fn load(config: &GatewayJwtConfig) -> ryno_core::Result<LaunchSigningAuthorities> {
    let signing_pem = std::fs::read(&config.signing_key_path).map_err(|error| {
        Error::config(format!(
            "cannot read sandbox launch-signing private key from {}: {error}",
            config.signing_key_path.display()
        ))
    })?;
    let public_pem = std::fs::read(&config.public_key_path).map_err(|error| {
        Error::config(format!(
            "cannot read sandbox launch-signing public key from {}: {error}",
            config.public_key_path.display()
        ))
    })?;
    let kid = std::fs::read_to_string(&config.kid_path)
        .map_err(|error| {
            Error::config(format!(
                "cannot read sandbox launch-signing key ID from {}: {error}",
                config.kid_path.display()
            ))
        })?
        .trim()
        .to_string();
    if kid.is_empty() {
        return Err(Error::config(format!(
            "sandbox launch-signing key ID file {} is empty",
            config.kid_path.display()
        )));
    }
    let extension = ExtensionJwtIssuer::from_pem(
        &signing_pem,
        &public_pem,
        kid.clone(),
        &config.gateway_id,
        config.token_ttl(),
    )
    .map_err(|_| {
        Error::config(
            "invalid sandbox launch-signing bundle: expected Ed25519 private and public keys",
        )
    })?;
    let sandbox_session = SandboxSessionJwtAuthority::from_pem(
        &signing_pem,
        &public_pem,
        kid,
        &config.gateway_id,
        config.sandbox_token_ttl(),
    )
    .map_err(|error| {
        // This constructor maps core SessionJwtError variants to fixed text;
        // preserve their actionable field and lifetime diagnostics.
        Error::config(format!("invalid sandbox launch-signing bundle: {error}"))
    })?;

    // Parsing two keys does not establish that they are a pair. Sign and verify
    // a local probe so mismatched keys fail before a driver prepares an image.
    // The probe is never persisted or sent to a driver or supervisor.
    let identity = super::sandbox_session::PersistedSandboxIdentity::new()
        .map_err(|_| Error::config("cannot initialize sandbox launch-signing validation"))?;
    let probe = sandbox_session
        .mint_persisted_launch("launch-signing-preflight", &identity)
        .map_err(|_| Error::config("sandbox launch-signing key cannot mint session credentials"))?;
    sandbox_session
        .verify_gateway_token(probe.supervisor.gateway_token.expose_secret())
        .map_err(|_| {
            Error::config("sandbox launch-signing private and public keys do not match")
        })?;

    Ok(LaunchSigningAuthorities {
        extension: Arc::new(extension),
        sandbox_session: Arc::new(sandbox_session),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ryno_bootstrap::jwt::generate_jwt_key;

    fn bundle(directory: &std::path::Path) -> GatewayJwtConfig {
        let material = generate_jwt_key().expect("generate signing material");
        std::fs::create_dir_all(directory).unwrap();
        let config = GatewayJwtConfig {
            signing_key_path: directory.join("signing.pem"),
            public_key_path: directory.join("public.pem"),
            kid_path: directory.join("kid"),
            gateway_id: "test-gateway".to_string(),
            ttl_secs: None,
        };
        std::fs::write(&config.signing_key_path, material.signing_key_pem).unwrap();
        std::fs::write(&config.public_key_path, material.public_key_pem).unwrap();
        std::fs::write(&config.kid_path, material.kid).unwrap();
        config
    }

    fn failure(config: &GatewayJwtConfig) -> String {
        match load(config) {
            Ok(_) => panic!("invalid bundle must fail before driver startup"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn explicit_bundle_mints_and_verifies_launch_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        assert!(load(&config).is_ok());
    }

    #[test]
    fn discovered_bundle_mints_and_verifies_launch_credentials() {
        let directory = tempfile::tempdir().unwrap();
        bundle(&directory.path().join("jwt"));
        let config = crate::defaults::local_jwt_config(directory.path())
            .unwrap()
            .unwrap();
        assert!(load(&config).is_ok());
    }

    #[test]
    fn missing_signing_file_names_the_required_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        std::fs::remove_file(&config.signing_key_path).unwrap();
        let error = failure(&config);
        assert!(error.contains("cannot read sandbox launch-signing private key"));
        assert!(error.contains("signing.pem"));
    }

    #[test]
    fn invalid_signing_metadata_keeps_specific_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = bundle(directory.path());
        config.ttl_secs = std::num::NonZeroU64::new(1);
        assert!(failure(&config).contains("between 60 and 3600 seconds"));
        config.ttl_secs = None;
        config.gateway_id = "invalid gateway secret-marker".to_string();
        let error = failure(&config);
        assert!(error.contains("gateway ID is invalid"));
        assert!(!error.contains("secret-marker"));
        config.gateway_id = "valid-gateway".to_string();
        std::fs::write(&config.kid_path, "invalid kid secret-marker").unwrap();
        let error = failure(&config);
        assert!(error.contains("key ID is invalid"));
        assert!(!error.contains("secret-marker"));
    }

    #[test]
    fn missing_public_key_and_key_id_name_the_required_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        std::fs::remove_file(&config.public_key_path).unwrap();
        assert!(failure(&config).contains("cannot read sandbox launch-signing public key"));
        let config = bundle(directory.path());
        std::fs::remove_file(&config.kid_path).unwrap();
        assert!(failure(&config).contains("cannot read sandbox launch-signing key ID"));
    }

    #[test]
    fn malformed_signing_material_is_not_in_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        let marker = "secret-marker-that-must-not-be-logged";
        std::fs::write(&config.signing_key_path, marker).unwrap();
        let error = failure(&config);
        assert!(error.contains("invalid sandbox launch-signing bundle"));
        assert!(!error.contains(marker));
    }

    #[test]
    fn empty_key_id_is_reported_before_driver_startup() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        std::fs::write(&config.kid_path, " \n").unwrap();
        assert!(failure(&config).contains("is empty"));
    }

    #[test]
    fn mismatched_keys_are_rejected_before_driver_startup() {
        let directory = tempfile::tempdir().unwrap();
        let config = bundle(directory.path());
        let other = generate_jwt_key().unwrap();
        std::fs::write(&config.public_key_path, other.public_key_pem).unwrap();
        assert!(failure(&config).contains("private and public keys do not match"));
    }
}
