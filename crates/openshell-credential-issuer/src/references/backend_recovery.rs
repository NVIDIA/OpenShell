// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Side-effect-free recovery preflight, before any incompatible conversion.

use crate::IssuerConfig;
use openshell_core::extension_protocol::{ExtensionFamily, NegotiatedExtension};
use tonic::Status;

pub use openshell_driver_kubernetes_secrets::RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY;

/// Check the effective selected backend before preparing inline output or
/// refresh-material writes, switching bindings, or setting irreversible markers.
///
/// In-tree adapters have reviewed attempt-identity semantics. A configured UDS
/// driver must explicitly advertise verified immutable-attempt recovery; its
/// configured name alone is not evidence. This does not make upstream OAuth
/// calls idempotent or guarantee that every uncertain orphan is enumerable.
pub fn validate_activation(
    config: &IssuerConfig,
    negotiated: &[NegotiatedExtension],
) -> Result<(), Status> {
    // Match the existing registry's trimmed, deduplicated selection semantics.
    let enabled: std::collections::BTreeSet<_> = config
        .credential_drivers
        .iter()
        .map(|driver| driver.trim())
        .collect();
    if enabled.len() > 1 {
        return Err(Status::invalid_argument(
            "versioned credentials require one selected credential backend",
        ));
    }
    let selected = enabled.first().copied();
    let default = config
        .default_credential_driver
        .as_deref()
        .map(str::trim)
        .filter(|driver| !driver.is_empty());
    if selected == Some("") || default.is_some_and(|driver| Some(driver) != selected) {
        return Err(Status::invalid_argument(
            "credential backend selection is inconsistent",
        ));
    }
    let driver = selected.unwrap_or(openshell_driver_db_credstore::DRIVER_NAME);
    let table = config
        .driver_configs
        .get(driver)
        .map(|value| {
            value.as_table().ok_or_else(|| {
                Status::invalid_argument("credential driver configuration must be a table")
            })
        })
        .transpose()?;
    let transport = table
        .and_then(|table| table.get("transport"))
        .map(|value| {
            value.as_str().ok_or_else(|| {
                Status::invalid_argument("credential driver transport must be a string")
            })
        })
        .transpose()?;
    let uds = match transport {
        Some("uds") => true,
        None | Some("in_tree") => false,
        Some(_) => {
            return Err(Status::invalid_argument(
                "unsupported credential driver transport",
            ));
        }
    };
    if uds {
        if negotiated.iter().any(|extension| {
            extension.family == ExtensionFamily::Credentials
                && extension.configured_name == driver
                && extension
                    .supported_capabilities
                    .iter()
                    .any(|capability| capability == RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY)
        }) {
            return Ok(());
        }
        return Err(Status::failed_precondition(format!(
            "versioned credential activation is unsupported for UDS driver '{driver}': required capability {RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY} is absent; no conversion may begin"
        )));
    }
    let known_builtin = matches!(driver, "vault" | "kubernetes-secrets")
        || driver == openshell_driver_db_credstore::DRIVER_NAME;
    let test_backend = cfg!(any(test, feature = "test-support")) && driver == "test-static";
    if known_builtin || test_backend {
        return Ok(());
    }
    Err(Status::failed_precondition(format!(
        "versioned credential activation is unsupported for backend '{driver}': recoverable attempt identity is not established"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::extension_protocol::{extension_metadata, gateway_metadata, negotiate};

    fn uds_config(driver: &str) -> IssuerConfig {
        IssuerConfig {
            credential_drivers: vec![driver.to_owned()],
            default_credential_driver: Some(driver.to_owned()),
            driver_configs: std::collections::BTreeMap::from([(
                driver.to_owned(),
                toml::Value::Table(toml::toml! { transport = "uds" }),
            )]),
            ..IssuerConfig::default()
        }
    }

    fn extension(driver: &str, recoverable: bool) -> NegotiatedExtension {
        negotiate(
            ExtensionFamily::Credentials,
            driver,
            &gateway_metadata(ExtensionFamily::Credentials),
            Some(extension_metadata(
                ExtensionFamily::Credentials,
                format!("test/{driver}"),
                "1",
                if recoverable {
                    vec![RECOVERABLE_IMMUTABLE_WRITE_CAPABILITY.to_owned()]
                } else {
                    Vec::new()
                },
            )),
        )
        .unwrap()
    }

    #[test]
    fn selected_in_tree_backends_pass_without_uds_capability() {
        validate_activation(&IssuerConfig::default(), &[]).unwrap();
        for driver in ["vault", "kubernetes-secrets"] {
            let config = IssuerConfig {
                credential_drivers: vec![driver.to_owned()],
                ..IssuerConfig::default()
            };
            validate_activation(&config, &[]).unwrap();
        }
    }

    #[test]
    fn preflight_preserves_registry_whitespace_deduplication_and_empty_default_semantics() {
        let config = IssuerConfig {
            credential_drivers: vec![" vault ".into(), "vault".into()],
            default_credential_driver: Some(" vault ".into()),
            ..IssuerConfig::default()
        };
        validate_activation(&config, &[]).unwrap();
        let config = IssuerConfig {
            default_credential_driver: Some(" ".into()),
            ..IssuerConfig::default()
        };
        validate_activation(&config, &[]).unwrap();
    }

    #[test]
    fn uds_requires_the_selected_drivers_explicit_recovery_contract() {
        for driver in ["vault", "kubernetes-secrets", "custom-uds"] {
            let config = uds_config(driver);
            assert_eq!(
                validate_activation(&config, &[]).unwrap_err().code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                validate_activation(&config, &[extension(driver, false)])
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            assert_eq!(
                validate_activation(&config, &[extension("another-driver", true)])
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
            validate_activation(&config, &[extension(driver, true)]).unwrap();
        }
    }
}
