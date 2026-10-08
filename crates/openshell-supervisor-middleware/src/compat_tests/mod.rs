// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! 0.1.x characterization of the legacy HTTP and WebSocket middleware protocol.
//!
//! Every suite talks to a service generated from the released v0.1.2 schema
//! (`openshell-supervisor-middleware-wire-fixture`) through
//! [`crate::MiddlewareRegistry::connect_services`], the registration path the
//! gateway and supervisor use. HTTP request and response chains run through
//! [`harness`]. Request chains run on the request pipeline, where legacy
//! entries are request adapter stages. Response chains name the
//! [`harness::Engine`] that executes them; the response cutover adds an
//! engine variant to [`harness::Engine::ALL`] and reruns those suites.
//! WebSocket and registration tests call the runner and registry directly,
//! because WebSocket bindings keep their 0.1.x engine.
//!
//! An expectation here changes only when the adapters deliberately differ
//! from 0.1.x (issue #2431). Tests that pin such a 0.1.x behavior say so next
//! to the assertion, so a cutover changes it on purpose rather than by
//! accident.

pub mod harness;
mod request;
mod response;
mod websocket;
