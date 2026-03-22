// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layers for dual-file OCSF output and event bridging.
//!
//! - [`OcsfShorthandLayer`] writes human-readable shorthand to a writer
//! - [`OcsfJsonlLayer`] writes OCSF JSONL to a writer
//! - [`emit_ocsf_event`] bridges `OcsfEvent` structs into the tracing system

pub(crate) mod event_bridge;
mod jsonl_layer;
mod shorthand_layer;

pub use event_bridge::emit_ocsf_event;
pub use jsonl_layer::OcsfJsonlLayer;
pub use shorthand_layer::OcsfShorthandLayer;
