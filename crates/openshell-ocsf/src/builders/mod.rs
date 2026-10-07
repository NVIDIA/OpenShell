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
/// ```
macro_rules! impl_builder_setters {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
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
    ($builder:ident, no_status) => {
        impl<'a> $builder<'a> {
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
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the event activity identifier.
            #[must_use]
            pub fn activity(mut self, id: $crate::enums::ActivityId) -> Self {
                self.activity = id;
                self
            }
        }
    };
}

/// Generate `action` and `disposition` setters shared by network, HTTP, SSH,
/// process, and detection-finding builders.
macro_rules! impl_action_disposition_setters {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
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
mod base;
mod config;
mod finding;
mod http;
mod lifecycle;
mod network;
mod process;
mod ssh;

pub use api_activity::ApiActivityBuilder;
pub use base::BaseEventBuilder;
pub use config::ConfigStateChangeBuilder;
pub use finding::DetectionFindingBuilder;
pub use http::HttpActivityBuilder;
pub use lifecycle::AppLifecycleBuilder;
pub use network::NetworkActivityBuilder;
pub use process::ProcessActivityBuilder;
pub use ssh::SshActivityBuilder;

use std::net::IpAddr;

use crate::OCSF_VERSION;
use crate::enums::StatusId;
use crate::events::base_event::BaseEventData;
use crate::objects::{Container, Device, Endpoint, Image, Metadata, Product};

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
    /// Container image reference.
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
            image: (!self.container_image.is_empty()).then(|| Image {
                name: self.container_image.clone(),
            }),
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
    /// optional status, optional message, device info, and container info.
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
        base.set_device(self.device());
        if let Some(container) = self.container() {
            base.set_container(container);
        }
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
        HttpRequest, HttpResponse, Process, SeverityId, StateId, Url,
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
                .finding_info(FindingInfo::new("finding-1", "Nonce replay"))
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
    ]
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

    #[test]
    fn test_emitted_device_matches_vendored_schema() {
        use crate::validation::schema::{
            load_object_schema, validate_enum_value, validate_required_fields,
        };

        let device = serde_json::to_value(test_sandbox_context().device()).unwrap();
        let schema = load_object_schema("device");
        validate_required_fields(&device, &schema);
        validate_enum_value(&device, "type_id", &schema);
    }

    /// One event per builder, built with a production-like sandbox context
    /// (container image set), must validate against the vendored 1.8.0 schemas.
    #[test]
    fn every_builder_emits_schema_conformant_events() {
        use crate::validation::schema::{load_class_schema, validate_required_fields};

        let ctx = test_sandbox_context();
        let events = sample_events(&ctx);
        for (class, event) in &events {
            let json = event.to_json().unwrap();
            validate_required_fields(&json, &load_class_schema(class));
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
