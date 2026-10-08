// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared version and capability negotiation for `OpenShell` extensions.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::proto::extension::v1::{PeerMetadata, ProtocolVersion};

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

/// Capability for compute drivers that require gateway-minted launch credentials.
///
/// Drivers require this capability when every launch needs a
/// [`crate::jwt::SandboxLaunchAuthentication`] bundle. The gateway checks its
/// configured signer before accepting sandbox creation.
pub const COMPUTE_LAUNCH_AUTHENTICATION: &str = "openshell.compute.launch-authentication";

/// Capability for supervisor-middleware peers that execute version 2 of the
/// HTTP middleware protocol (`EvaluateHttp`).
///
/// A service that implements only version 2 requires this capability, so a
/// peer without version 2 support refuses it at Describe. A service that
/// implements both protocols returns version 2 HTTP bindings only to callers
/// that advertise it, and legacy HTTP bindings otherwise.
pub const SUPERVISOR_MIDDLEWARE_HTTP_V2: &str = "openshell.supervisor-middleware.http-v2";

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

/// Optional capabilities every `OpenShell` peer implements for `family`,
/// beyond the family contract.
const fn family_capabilities(family: ExtensionFamily) -> &'static [&'static str] {
    match family {
        ExtensionFamily::Compute => &[COMPUTE_LAUNCH_AUTHENTICATION],
        ExtensionFamily::Credentials
        | ExtensionFamily::GatewayInterceptor
        | ExtensionFamily::SupervisorMiddleware => &[],
    }
}

#[must_use]
pub fn gateway_metadata(family: ExtensionFamily) -> PeerMetadata {
    gateway_metadata_with_capabilities(family, [])
}

/// Gateway or supervisor metadata with additional optional capabilities.
///
/// Callers advertise capabilities they implement for `family`, such as
/// [`SUPERVISOR_MIDDLEWARE_HTTP_V2`] once their middleware runtime executes
/// version 2 HTTP.
#[must_use]
pub fn gateway_metadata_with_capabilities(
    family: ExtensionFamily,
    additional_capabilities: impl IntoIterator<Item = String>,
) -> PeerMetadata {
    let contract = family.contract_capability();
    let mut supported_capabilities = vec![contract.clone()];
    for capability in family_capabilities(family)
        .iter()
        .map(|capability| (*capability).to_string())
        .chain(additional_capabilities)
    {
        if !supported_capabilities.contains(&capability) {
            supported_capabilities.push(capability);
        }
    }
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: "openshell/gateway".to_string(),
        implementation_version: crate::VERSION.to_string(),
        supported_capabilities,
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

/// Extension metadata that also requires `required_capabilities` from the
/// gateway or supervisor. Each required capability is advertised as supported
/// too.
#[must_use]
pub fn extension_metadata_with_requirements(
    family: ExtensionFamily,
    implementation_name: impl Into<String>,
    implementation_version: impl Into<String>,
    additional_capabilities: impl IntoIterator<Item = String>,
    required_capabilities: impl IntoIterator<Item = String>,
) -> PeerMetadata {
    let mut metadata = extension_metadata(
        family,
        implementation_name,
        implementation_version,
        additional_capabilities,
    );
    for capability in required_capabilities {
        if !metadata.supported_capabilities.contains(&capability) {
            metadata.supported_capabilities.push(capability.clone());
        }
        if !metadata.required_capabilities.contains(&capability) {
            metadata.required_capabilities.push(capability);
        }
    }
    metadata
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
    fn gateway_metadata_advertises_family_capabilities_once() {
        let compute = gateway_metadata(ExtensionFamily::Compute);
        assert!(
            compute
                .supported_capabilities
                .contains(&COMPUTE_LAUNCH_AUTHENTICATION.to_string())
        );

        let middleware = gateway_metadata(ExtensionFamily::SupervisorMiddleware);
        assert_eq!(
            middleware.supported_capabilities,
            vec!["openshell.supervisor-middleware.contract"]
        );
        let middleware = gateway_metadata_with_capabilities(
            ExtensionFamily::SupervisorMiddleware,
            [
                SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string(),
                SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string(),
            ],
        );
        assert_eq!(
            middleware.supported_capabilities,
            vec![
                "openshell.supervisor-middleware.contract",
                SUPERVISOR_MIDDLEWARE_HTTP_V2
            ]
        );
        assert_eq!(
            middleware.protocol_version,
            Some(ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            })
        );
    }

    #[test]
    fn extension_requiring_http_v2_negotiates_only_with_peers_that_advertise_it() {
        let extension = extension_metadata_with_requirements(
            ExtensionFamily::SupervisorMiddleware,
            "example/v2-only",
            "1.0.0",
            [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
            [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
        );
        assert_eq!(
            extension
                .supported_capabilities
                .iter()
                .filter(|capability| *capability == SUPERVISOR_MIDDLEWARE_HTTP_V2)
                .count(),
            1
        );
        assert_eq!(
            extension.required_capabilities,
            vec![
                "openshell.supervisor-middleware.contract",
                SUPERVISOR_MIDDLEWARE_HTTP_V2
            ]
        );

        let legacy_peer = gateway_metadata(ExtensionFamily::SupervisorMiddleware);
        let error = negotiate(
            ExtensionFamily::SupervisorMiddleware,
            "guard",
            &legacy_peer,
            Some(extension.clone()),
        )
        .unwrap_err();
        assert_eq!(
            error,
            NegotiationError::MissingGatewayCapabilities {
                family: "supervisor-middleware",
                name: "guard".to_string(),
                capabilities: SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string(),
            }
        );

        let v2_peer = gateway_metadata_with_capabilities(
            ExtensionFamily::SupervisorMiddleware,
            [SUPERVISOR_MIDDLEWARE_HTTP_V2.to_string()],
        );
        let negotiated = negotiate(
            ExtensionFamily::SupervisorMiddleware,
            "guard",
            &v2_peer,
            Some(extension),
        )
        .expect("a peer that advertises http-v2 accepts a v2-only service");
        assert_eq!(negotiated.protocol_major, PROTOCOL_MAJOR);
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
