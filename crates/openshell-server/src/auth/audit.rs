// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF security events for gateway authentication outcomes.
//!
//! Events carry a low-cardinality reason category, never presented
//! credentials or raw verification errors.

use openshell_ocsf::{
    ActionId, AuthenticationBuilder, DispositionId, HttpMethod, HttpRequest, Service, SeverityId,
    StatusId, Url, User, ocsf_emit,
};

/// Why an authentication attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// No credential was presented.
    MissingCredential,
    /// Credentials for more than one mechanism were presented together.
    ConflictingCredentials,
}

impl AuthFailureReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::ConflictingCredentials => "conflicting_credentials",
        }
    }

    fn severity(self) -> SeverityId {
        match self {
            Self::MissingCredential => SeverityId::Low,
            Self::ConflictingCredentials => SeverityId::Medium,
        }
    }
}

/// The mechanism a caller attempted to authenticate with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    Mtls,
}

impl AuthMechanism {
    fn label(self) -> &'static str {
        match self {
            Self::Mtls => "mtls",
        }
    }
}

/// Emit an Authentication failure event for a gRPC request to `path`.
pub fn emit_authentication_failure(
    path: &str,
    mechanism: Option<AuthMechanism>,
    reason: AuthFailureReason,
) {
    let ctx = crate::gateway_ocsf::context("", "");
    let mut builder = AuthenticationBuilder::new(
        &ctx,
        User::unidentified(),
        Service::new("openshell-gateway"),
    )
    .action(ActionId::Denied)
    .disposition(DispositionId::Blocked)
    .severity(reason.severity())
    .status(StatusId::Failure)
    .status_detail(reason.as_str())
    .http_request(HttpRequest {
        http_method: HttpMethod::Post,
        url: Some(Url::from_path(path)),
    })
    .message(format!("authentication failed: {}", reason.as_str()));
    if let Some(mechanism) = mechanism {
        builder = builder.auth_protocol_other(mechanism.label());
    }
    ocsf_emit!(builder.build());
}
