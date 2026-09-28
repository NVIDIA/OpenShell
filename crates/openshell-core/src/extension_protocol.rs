// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared version and capability negotiation for `OpenShell` extensions.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::proto::extension::v1::{PeerMetadata, ProtocolVersion};

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

const MAX_IMPLEMENTATION_NAME_BYTES: usize = 128;
const MAX_IMPLEMENTATION_VERSION_BYTES: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExtensionFamily {
    Compute,
    Credentials,
    GatewayInterceptor,
    SupervisorMiddleware,
}

impl ExtensionFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compute => "compute",
            Self::Credentials => "credentials",
            Self::GatewayInterceptor => "gateway-interceptor",
            Self::SupervisorMiddleware => "supervisor-middleware",
        }
    }

    #[must_use]
    pub fn contract_capability(self) -> String {
        format!("openshell.{}.contract", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedExtension {
    pub family: ExtensionFamily,
    pub configured_name: String,
    pub implementation_name: String,
    pub implementation_version: String,
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub supported_capabilities: Vec<String>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NegotiationError {
    #[error(
        "{family} extension '{name}' did not provide protocol metadata; upgrade the extension to a version that supports OpenShell extension negotiation"
    )]
    MissingMetadata { family: &'static str, name: String },
    #[error(
        "gateway did not provide protocol metadata to {family} extension '{name}'; upgrade the gateway and extension together"
    )]
    MissingGatewayMetadata { family: &'static str, name: String },
    #[error("{family} extension '{name}' did not provide a protocol version")]
    MissingProtocolVersion { family: &'static str, name: String },
    #[error(
        "{family} extension '{name}' uses unsupported protocol {remote_major}.{remote_minor}; gateway supports {local_major}.{local_minor}"
    )]
    IncompatibleProtocol {
        family: &'static str,
        name: String,
        remote_major: u32,
        remote_minor: u32,
        local_major: u32,
        local_minor: u32,
    },
    #[error("{family} extension '{name}' has invalid {field}: {reason}")]
    InvalidMetadata {
        family: &'static str,
        name: String,
        field: &'static str,
        reason: String,
    },
    #[error("{family} extension '{name}' is missing required capabilities: {capabilities}")]
    MissingExtensionCapabilities {
        family: &'static str,
        name: String,
        capabilities: String,
    },
    #[error(
        "gateway is missing capabilities required by {family} extension '{name}': {capabilities}"
    )]
    MissingGatewayCapabilities {
        family: &'static str,
        name: String,
        capabilities: String,
    },
}

#[must_use]
pub fn gateway_metadata(family: ExtensionFamily) -> PeerMetadata {
    let contract = family.contract_capability();
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: "openshell/gateway".to_string(),
        implementation_version: crate::VERSION.to_string(),
        supported_capabilities: vec![contract.clone()],
        required_capabilities: vec![contract],
    }
}

#[must_use]
pub fn extension_metadata(
    family: ExtensionFamily,
    implementation_name: impl Into<String>,
    implementation_version: impl Into<String>,
    additional_capabilities: impl IntoIterator<Item = String>,
) -> PeerMetadata {
    let contract = family.contract_capability();
    let mut supported_capabilities = vec![contract.clone()];
    supported_capabilities.extend(additional_capabilities);
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: implementation_name.into(),
        implementation_version: implementation_version.into(),
        supported_capabilities,
        required_capabilities: vec![contract],
    }
}

pub fn negotiate(
    family: ExtensionFamily,
    configured_name: impl Into<String>,
    gateway: &PeerMetadata,
    extension: Option<PeerMetadata>,
) -> Result<NegotiatedExtension, NegotiationError> {
    let configured_name = configured_name.into();
    let family_name = family.as_str();
    let extension = extension.ok_or_else(|| NegotiationError::MissingMetadata {
        family: family_name,
        name: configured_name.clone(),
    })?;
    let version = extension.protocol_version.as_ref().ok_or_else(|| {
        NegotiationError::MissingProtocolVersion {
            family: family_name,
            name: configured_name.clone(),
        }
    })?;
    let gateway_version = gateway.protocol_version.as_ref().ok_or_else(|| {
        NegotiationError::MissingProtocolVersion {
            family: family_name,
            name: "gateway".to_string(),
        }
    })?;
    if version.major != gateway_version.major {
        return Err(NegotiationError::IncompatibleProtocol {
            family: family_name,
            name: configured_name,
            remote_major: version.major,
            remote_minor: version.minor,
            local_major: gateway_version.major,
            local_minor: gateway_version.minor,
        });
    }

    validate_text(
        family_name,
        &configured_name,
        "implementation_name",
        &extension.implementation_name,
        MAX_IMPLEMENTATION_NAME_BYTES,
    )?;
    validate_text(
        family_name,
        &configured_name,
        "implementation_version",
        &extension.implementation_version,
        MAX_IMPLEMENTATION_VERSION_BYTES,
    )?;
    let extension_supported = normalize_capabilities(
        family_name,
        &configured_name,
        "supported_capabilities",
        &extension.supported_capabilities,
    )?;
    let extension_required = normalize_capabilities(
        family_name,
        &configured_name,
        "required_capabilities",
        &extension.required_capabilities,
    )?;
    let gateway_supported = normalize_capabilities(
        family_name,
        "gateway",
        "supported_capabilities",
        &gateway.supported_capabilities,
    )?;
    let gateway_required = normalize_capabilities(
        family_name,
        "gateway",
        "required_capabilities",
        &gateway.required_capabilities,
    )?;

    let missing_extension = gateway_required
        .difference(&extension_supported)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_extension.is_empty() {
        return Err(NegotiationError::MissingExtensionCapabilities {
            family: family_name,
            name: configured_name,
            capabilities: missing_extension.join(", "),
        });
    }
    let missing_gateway = extension_required
        .difference(&gateway_supported)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_gateway.is_empty() {
        return Err(NegotiationError::MissingGatewayCapabilities {
            family: family_name,
            name: configured_name,
            capabilities: missing_gateway.join(", "),
        });
    }

    Ok(NegotiatedExtension {
        family,
        configured_name,
        implementation_name: extension.implementation_name,
        implementation_version: extension.implementation_version,
        protocol_major: version.major,
        protocol_minor: version.minor,
        supported_capabilities: extension_supported.into_iter().collect(),
        required_capabilities: extension_required.into_iter().collect(),
    })
}

pub fn validate_gateway_metadata(
    family: ExtensionFamily,
    extension_name: impl Into<String>,
    extension: Option<&PeerMetadata>,
    gateway: Option<PeerMetadata>,
) -> Result<(), NegotiationError> {
    let extension_name = extension_name.into();
    let gateway = gateway.ok_or_else(|| NegotiationError::MissingGatewayMetadata {
        family: family.as_str(),
        name: extension_name.clone(),
    })?;
    negotiate(family, extension_name, &gateway, extension.cloned()).map(drop)
}

fn validate_text(
    family: &'static str,
    name: &str,
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), NegotiationError> {
    let reason = if value.trim().is_empty() {
        Some("must not be empty".to_string())
    } else if value.len() > max_bytes {
        Some(format!("must be at most {max_bytes} bytes"))
    } else if value.chars().any(char::is_control) {
        Some("must not contain control characters".to_string())
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(NegotiationError::InvalidMetadata {
            family,
            name: name.to_string(),
            field,
            reason,
        });
    }
    Ok(())
}

fn normalize_capabilities(
    family: &'static str,
    name: &str,
    field: &'static str,
    capabilities: &[String],
) -> Result<BTreeSet<String>, NegotiationError> {
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(NegotiationError::InvalidMetadata {
            family,
            name: name.to_string(),
            field,
            reason: format!("must contain at most {MAX_CAPABILITIES} entries"),
        });
    }
    let mut normalized = BTreeSet::new();
    for capability in capabilities {
        if !valid_capability(capability) {
            return Err(NegotiationError::InvalidMetadata {
                family,
                name: name.to_string(),
                field,
                reason: format!("'{capability}' must be a lowercase namespaced identifier"),
            });
        }
        if !normalized.insert(capability.clone()) {
            return Err(NegotiationError::InvalidMetadata {
                family,
                name: name.to_string(),
                field,
                reason: format!("contains duplicate '{capability}'"),
            });
        }
    }
    Ok(normalized)
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CAPABILITY_BYTES
        && value.starts_with("openshell.")
        && value.split('.').count() >= 3
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compatible() -> (PeerMetadata, PeerMetadata) {
        let gateway = gateway_metadata(ExtensionFamily::Compute);
        let extension = extension_metadata(
            ExtensionFamily::Compute,
            "example/compute",
            "2.3.4",
            ["openshell.compute.optional-future".to_string()],
        );
        (gateway, extension)
    }

    #[test]
    fn compatible_metadata_negotiates_and_sorts_unknown_optional_capabilities() {
        let (gateway, mut extension) = compatible();
        extension.supported_capabilities.reverse();
        let result = negotiate(
            ExtensionFamily::Compute,
            "example",
            &gateway,
            Some(extension),
        )
        .unwrap();
        assert_eq!(result.protocol_major, 1);
        assert_eq!(
            result.supported_capabilities,
            vec![
                "openshell.compute.contract",
                "openshell.compute.optional-future"
            ]
        );
    }

    #[test]
    fn same_major_minor_skew_is_compatible() {
        let (gateway, mut extension) = compatible();
        extension.protocol_version.as_mut().unwrap().minor = 99;
        assert!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension)
            )
            .is_ok()
        );
    }

    #[test]
    fn missing_metadata_and_major_skew_are_actionable() {
        let (gateway, mut extension) = compatible();
        assert!(matches!(
            negotiate(ExtensionFamily::Compute, "example", &gateway, None),
            Err(NegotiationError::MissingMetadata { .. })
        ));
        extension.protocol_version.as_mut().unwrap().major = 2;
        assert!(matches!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension)
            ),
            Err(NegotiationError::IncompatibleProtocol { .. })
        ));
    }

    #[test]
    fn both_peers_require_capabilities_from_the_other() {
        let (mut gateway, mut extension) = compatible();
        gateway
            .required_capabilities
            .push("openshell.compute.gateway-required".to_string());
        assert!(matches!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension.clone())
            ),
            Err(NegotiationError::MissingExtensionCapabilities { .. })
        ));

        gateway.required_capabilities.pop();
        extension
            .required_capabilities
            .push("openshell.compute.extension-required".to_string());
        assert!(matches!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension)
            ),
            Err(NegotiationError::MissingGatewayCapabilities { .. })
        ));
    }

    #[test]
    fn malformed_and_duplicate_capabilities_are_rejected() {
        let (gateway, mut extension) = compatible();
        extension
            .supported_capabilities
            .push("NOT-NAMESPACED".to_string());
        assert!(matches!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension)
            ),
            Err(NegotiationError::InvalidMetadata { .. })
        ));

        let (gateway, mut extension) = compatible();
        extension
            .supported_capabilities
            .push("openshell.compute.contract".to_string());
        assert!(matches!(
            negotiate(
                ExtensionFamily::Compute,
                "example",
                &gateway,
                Some(extension)
            ),
            Err(NegotiationError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn extension_side_rejects_missing_and_incompatible_gateway_metadata() {
        let (mut gateway, extension) = compatible();
        assert!(matches!(
            validate_gateway_metadata(ExtensionFamily::Compute, "example", Some(&extension), None,),
            Err(NegotiationError::MissingGatewayMetadata { .. })
        ));

        gateway.protocol_version.as_mut().unwrap().major = 2;
        assert!(matches!(
            validate_gateway_metadata(
                ExtensionFamily::Compute,
                "example",
                Some(&extension),
                Some(gateway),
            ),
            Err(NegotiationError::IncompatibleProtocol { .. })
        ));
    }
}
