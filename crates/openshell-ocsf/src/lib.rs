// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! # openshell-ocsf
//!
//! OCSF v1.7.0 event types, formatters, and tracing layers for `OpenShell`
//! sandbox logging.
//!
//! This crate provides:
//! - **8 OCSF event classes**: Network Activity, HTTP Activity, SSH Activity,
//!   Process Activity, Detection Finding, Application Lifecycle, Device Config
//!   State Change, and Base Event
//! - **Typed enums and objects**: All OCSF enum and object types used by the
//!   event classes
//! - **Builders**: Ergonomic per-class builders with `SandboxContext` for shared
//!   metadata
//! - **Dual formatters**: `format_shorthand()` for human-readable single-line
//!   output, and `to_json()`/`to_json_line()` for OCSF-compliant JSONL
//! - **Tracing layers**: `OcsfShorthandLayer` and `OcsfJsonlLayer` for
//!   subscriber integration
//! - **`ocsf_emit!` macro**: Thin wrapper for emitting events through the
//!   tracing system

/// OCSF schema version this crate implements.
pub const OCSF_VERSION: &str = "1.7.0";

pub mod builders;
pub mod enums;
pub mod events;
pub mod format;
pub mod objects;
pub mod tracing_layers;

#[cfg(test)]
pub mod validation;

// --- Core event types ---
pub use events::{
    ApplicationLifecycleEvent, BaseEvent, BaseEventData, DetectionFindingEvent,
    DeviceConfigStateChangeEvent, HttpActivityEvent, NetworkActivityEvent, OcsfEvent,
    ProcessActivityEvent, SshActivityEvent,
};

// --- Enum types ---
pub use enums::{
    ActionId, ActivityId, AuthTypeId, ConfidenceId, DispositionId, HttpMethod, LaunchTypeId,
    OcsfEnum, RiskLevelId, SecurityLevelId, SeverityId, StateId, StatusId,
};

// --- Object types ---
pub use objects::{
    Actor, Attack, ConnectionInfo, Container, Device, Endpoint, Evidence, FindingInfo,
    FirewallRule, HttpRequest, HttpResponse, Image, Metadata, OsInfo, Process, Product,
    Remediation, Tactic, Technique, Url,
};

// --- Builders ---
pub use builders::{
    AppLifecycleBuilder, BaseEventBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    HttpActivityBuilder, NetworkActivityBuilder, ProcessActivityBuilder, SandboxContext,
    SshActivityBuilder,
};

// --- Tracing layers ---
pub use tracing_layers::{
    OCSF_TARGET, OcsfJsonlLayer, OcsfShorthandLayer, clone_current_event, emit_ocsf_event,
};
