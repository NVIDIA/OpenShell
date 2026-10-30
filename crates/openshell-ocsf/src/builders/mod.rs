// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ergonomic builders for constructing OCSF events.
//!
//! Each event class has a builder that takes a `EventContext` reference
//! and provides chainable methods for setting event fields.

/// Generate the shared `severity`, `status`, and `message` setter methods that
/// appear identically on every OCSF event builder in this crate.
///
/// # Usage
/// ```ignore
/// impl_builder_setters!(MyBuilder);            // severity + status + message
/// impl_builder_setters!(MyBuilder, no_status); // severity + message only
/// impl_builder_setters!(MyBuilder<State>);     // for a type-state builder
/// ```
macro_rules! impl_builder_setters {
    ($builder:ident $(<$state:ident>)?) => {
        impl<'a $(, $state)?> $builder<'a $(, $state)?> {
            /// Set the event severity.
            #[must_use]
            pub fn severity(mut self, id: $crate::enums::SeverityId) -> Self {
                self.severity = id;
                self
            }
            /// Set the overall event status.
            #[must_use]
            pub fn status(mut self, id: $crate::enums::StatusId) -> Self {
                self.status = Some(id);
                self
            }
            /// Set a human-readable event message.
            #[must_use]
            pub fn message(mut self, msg: impl Into<String>) -> Self {
                self.message = Some(msg.into());
                self
            }
        }
    };
    ($builder:ident $(<$state:ident>)?, no_status) => {
        impl<'a $(, $state)?> $builder<'a $(, $state)?> {
            /// Set the event severity.
            #[must_use]
            pub fn severity(mut self, id: $crate::enums::SeverityId) -> Self {
                self.severity = id;
                self
            }
            /// Set a human-readable event message.
            #[must_use]
            pub fn message(mut self, msg: impl Into<String>) -> Self {
                self.message = Some(msg.into());
                self
            }
        }
    };
}

/// Generate the `activity` setter used by every event builder that carries an
/// `activity` field.
macro_rules! impl_activity_setter {
    ($builder:ident $(<$state:ident>)?) => {
        impl<'a $(, $state)?> $builder<'a $(, $state)?> {
            /// Set the event activity identifier.
            #[must_use]
            pub fn activity(mut self, id: $crate::enums::ActivityId) -> Self {
                self.activity = id;
                self
            }
        }
    };
}

/// Generate `action` and `disposition` setters shared by every builder whose
/// event records an action and its disposition.
macro_rules! impl_action_disposition_setters {
    ($builder:ident $(<$state:ident>)?) => {
        impl<'a $(, $state)?> $builder<'a $(, $state)?> {
            /// Set the action taken.
            #[must_use]
            pub fn action(mut self, id: $crate::enums::ActionId) -> Self {
                self.action = Some(id);
                self
            }
            /// Set the disposition of the action.
            #[must_use]
            pub fn disposition(mut self, id: $crate::enums::DispositionId) -> Self {
                self.disposition = Some(id);
                self
            }
        }
    };
}

mod api_activity;
mod authentication;
mod base;
mod config;
mod finding;
mod http;
mod lifecycle;
mod network;
mod process;
mod ssh;

pub use api_activity::ApiActivityBuilder;
pub use authentication::AuthenticationBuilder;
pub use base::BaseEventBuilder;
pub use config::ConfigStateChangeBuilder;
pub use finding::DetectionFindingBuilder;
pub use http::HttpActivityBuilder;
pub use lifecycle::AppLifecycleBuilder;
pub use network::NetworkActivityBuilder;
pub use process::ProcessActivityBuilder;
pub use ssh::SshActivityBuilder;

use std::net::IpAddr;
use std::sync::Arc;

use crate::OCSF_VERSION;
use crate::enums::StatusId;
use crate::events::base_event::BaseEventData;
use crate::objects::{Container, Device, Endpoint, Metadata, Product};

/// Which `OpenShell` component produced an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOrigin {
    /// The supervisor process enforcing sandbox policy.
    Supervisor,
    /// The gateway process, which has no sandbox or container of its own.
    Gateway {
        /// Operator-assigned gateway name (`[openshell.gateway] name`).
        name: String,
    },
}

/// Immutable context created once at sandbox startup.
///
/// Passed to every event builder to populate shared OCSF fields
/// (metadata, container, device, proxy endpoint).
#[derive(Debug, Clone)]
pub struct EventContext {
    /// Sandbox unique identifier.
    pub sandbox_id: String,
    /// Sandbox display name.
    pub sandbox_name: String,
    /// Container image reference. Not emitted: OCSF requires an image `uid`.
    pub container_image: String,
    /// Device hostname.
    pub hostname: String,
    /// Product version string.
    pub product_version: String,
    /// Proxy listen IP address.
    pub proxy_ip: IpAddr,
    /// Proxy listen port.
    pub proxy_port: u16,
    /// Which component is emitting.
    pub origin: EventOrigin,
}

/// Event context borrowed from the caller or shared by a hosted sandbox
/// instance.
///
/// Builders accept either form, so events attributed to a hosted sandbox
/// instance need not leak a `'static` context for each instance.
#[derive(Debug, Clone)]
pub enum ContextRef<'a> {
    Borrowed(&'a EventContext),
    Shared(Arc<EventContext>),
}

impl std::ops::Deref for ContextRef<'_> {
    type Target = EventContext;

    fn deref(&self) -> &EventContext {
        match self {
            Self::Borrowed(context) => context,
            Self::Shared(context) => context,
        }
    }
}

impl<'a> From<&'a EventContext> for ContextRef<'a> {
    fn from(context: &'a EventContext) -> Self {
        Self::Borrowed(context)
    }
}

impl From<Arc<EventContext>> for ContextRef<'_> {
    fn from(context: Arc<EventContext>) -> Self {
        Self::Shared(context)
    }
}

impl<'a> From<&'a ContextRef<'_>> for ContextRef<'a> {
    fn from(context: &'a ContextRef<'_>) -> Self {
        Self::Borrowed(context)
    }
}

impl EventContext {
    /// Build the OCSF `Metadata` object for any event.
    #[must_use]
    pub fn metadata(&self, profiles: &[&str]) -> Metadata {
        let product = match self.origin {
            EventOrigin::Supervisor => Product::openshell_sandbox(&self.product_version),
            EventOrigin::Gateway { .. } => Product::openshell_gateway(&self.product_version),
        };
        Metadata {
            version: OCSF_VERSION.to_string(),
            product,
            profiles: profiles.iter().map(|s| (*s).to_string()).collect(),
            uid: Some(uuid::Uuid::new_v4().to_string()),
            log_source: None,
            correlation_uid: None,
        }
    }

    /// Build the OCSF `Container` object when the event concerns a sandbox.
    #[must_use]
    pub fn container(&self) -> Option<Container> {
        if self.sandbox_id.is_empty() {
            return None;
        }
        Some(Container {
            name: self.sandbox_name.clone(),
            uid: Some(self.sandbox_id.clone()),
        })
    }

    /// Build the OCSF `Device` object, stamped with the host OS this build runs
    /// on (Linux for the in-sandbox supervisor, Windows for the MXC gateway).
    #[must_use]
    pub fn device(&self) -> Device {
        match &self.origin {
            EventOrigin::Supervisor => Device::for_current_os(&self.hostname),
            EventOrigin::Gateway { name } => Device::gateway(&self.hostname, name),
        }
    }

    /// Build the `proxy_endpoint` object for the Network Proxy profile.
    #[must_use]
    pub fn proxy_endpoint(&self) -> Endpoint {
        Endpoint::from_ip(self.proxy_ip, self.proxy_port)
    }

    /// Apply the fields common to every builder's `build()` method onto `base`:
    /// optional status, optional message, and device info with its container.
    pub fn apply_common_fields(
        &self,
        base: &mut BaseEventData,
        status: Option<StatusId>,
        message: Option<String>,
    ) {
        if let Some(s) = status {
            base.set_status(s);
        }
        if let Some(m) = message {
            base.set_message(m);
        }
        base.set_device(self.device().with_container(self.container()));
    }
}

#[cfg(test)]
pub(crate) fn test_sandbox_context() -> EventContext {
    EventContext {
        sandbox_id: "sandbox-abc123".to_string(),
        sandbox_name: "my-sandbox".to_string(),
        container_image: "ghcr.io/openshell/sandbox:latest".to_string(),
        hostname: "sandbox-abc123".to_string(),
        product_version: "0.1.0".to_string(),
        proxy_ip: "10.42.0.1".parse().unwrap(),
        proxy_port: 3128,
        origin: EventOrigin::Supervisor,
    }
}

/// One event per builder, as production emits them, for schema conformance tests.
#[cfg(test)]
pub(crate) fn sample_events(ctx: &EventContext) -> Vec<(&'static str, crate::OcsfEvent)> {
    use crate::{
        ActionId, ActivityId, AiModel, ConnectionInfo, DispositionId, Endpoint, FindingInfo,
        HttpRequest, HttpResponse, Process, Service, SeverityId, StateId, Url, User,
    };

    let peer = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5));
    vec![
        (
            "network_activity",
            NetworkActivityBuilder::new(ctx)
                .activity(ActivityId::Open)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .src_endpoint_addr(peer, 51234)
                .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
                .connection_info(ConnectionInfo::new("tcp"))
                .actor_process(Process::new("curl", 42))
                .firewall_rule("default", "opa")
                .build(),
        ),
        (
            "http_activity",
            HttpActivityBuilder::new(ctx)
                .activity(ActivityId::Reset)
                .action(ActionId::Denied)
                .disposition(DispositionId::Blocked)
                .http_request(HttpRequest::new(
                    "GET",
                    Url::new("https", "api.example.com", "/v1", 443),
                ))
                .http_response(HttpResponse { code: 403 })
                .src_endpoint(Endpoint::from_ip(peer, 51234))
                .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
                .actor_process(Process::new("curl", 42))
                .build(),
        ),
        (
            "ssh_activity",
            SshActivityBuilder::new(ctx)
                .activity(ActivityId::Open)
                .src_endpoint_addr(peer, 44321)
                .dst_endpoint(Endpoint::from_domain("sandbox.local", 22))
                .build(),
        ),
        (
            "process_activity",
            ProcessActivityBuilder::new(ctx)
                .activity(ActivityId::Open)
                .process(Process::new("python3", 4713))
                .actor_process(Process::new("openshell-sandbox", 1))
                .build(),
        ),
        (
            "detection_finding",
            DetectionFindingBuilder::new(ctx)
                .activity(ActivityId::Open)
                .severity(SeverityId::High)
                .is_alert(true)
                .confidence(crate::ConfidenceId::High)
                .risk_level(crate::RiskLevelId::High)
                .finding_info(FindingInfo::new("finding-1", "Nonce replay"))
                .evidence_pairs(&[("nonce", "0xdeadbeef"), ("peer", "10.0.0.5")])
                .remediation("Rotate the sandbox SSH keys.")
                .attack(crate::Attack::mitre(
                    "T1550",
                    "Use Alternate Authentication Material",
                    "TA0008",
                    "Lateral Movement",
                ))
                .message("Nonce replay detected")
                .build(),
        ),
        (
            "application_lifecycle",
            AppLifecycleBuilder::new(ctx)
                .activity(ActivityId::Open)
                .build(),
        ),
        (
            "device_config_state_change",
            ConfigStateChangeBuilder::new(ctx)
                .state(StateId::Enabled, "loaded")
                .build(),
        ),
        ("base_event", BaseEventBuilder::new(ctx).build()),
        (
            "api_activity",
            ApiActivityBuilder::new(ctx, "chat.completions")
                .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
                .ai_model(AiModel::new("model", "provider"))
                .build(),
        ),
        (
            "authentication",
            AuthenticationBuilder::new(
                ctx,
                User::unidentified(),
                Service::new("openshell-gateway"),
            )
            .src_endpoint(Endpoint::from_ip(peer, 51234))
            .build(),
        ),
    ]
}

#[cfg(test)]
pub(crate) fn test_gateway_context() -> EventContext {
    EventContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: String::new(),
        hostname: "openshell-gateway-0".to_string(),
        product_version: "0.1.0".to_string(),
        proxy_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
        origin: EventOrigin::Gateway {
            name: "openshell".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_context_metadata() {
        let ctx = test_sandbox_context();
        let meta = ctx.metadata(&["security_control", "container"]);
        assert_eq!(meta.version, "1.8.0");
        assert_eq!(meta.product.name, "OpenShell Sandbox Supervisor");
        assert_eq!(meta.profiles.len(), 2);
        let uid = meta.uid.as_deref().expect("uid is set");
        assert!(!uid.is_empty());
        assert_ne!(uid, "sandbox-abc123");
    }

    /// One event per builder, built with a production-like sandbox context
    /// (container image set), must validate against the vendored 1.8.0 schemas.
    #[test]
    fn every_builder_emits_schema_conformant_events() {
        let ctx = test_sandbox_context();
        let events = sample_events(&ctx);
        for (class, event) in &events {
            let json = event.to_json().unwrap();
            openshell_ocsf_validate::validate_event(&json)
                .unwrap_or_else(|e| panic!("{class}: {e}"));
        }
    }

    #[test]
    fn test_sandbox_context_container() {
        let ctx = test_sandbox_context();
        let container = ctx.container().expect("sandbox context has a container");
        assert_eq!(container.name, "my-sandbox");
        assert_eq!(container.uid.as_deref(), Some("sandbox-abc123"));
    }

    #[test]
    fn test_sandbox_context_device() {
        let ctx = test_sandbox_context();
        let device = ctx.device();
        assert_eq!(device.hostname, "sandbox-abc123");
    }

    #[test]
    fn test_sandbox_context_proxy_endpoint() {
        let ctx = test_sandbox_context();
        let ep = ctx.proxy_endpoint();
        assert_eq!(ep.ip.as_deref(), Some("10.42.0.1"));
        assert_eq!(ep.port, Some(3128));
    }
}
