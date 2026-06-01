// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema types and pure-Rust parsing for `OpenShell` sandbox policies.
//!
//! This crate is intentionally dependency-light: `serde`, `serde_yml`,
//! `serde_json`, and `miette`. It has **no** dependency on `openshell-core`,
//! `tonic`, or `prost`, making it usable from projects that only need YAML
//! parsing and serialization without pulling in gRPC infrastructure.
//!
//! The types here are the **single canonical representation** of the YAML
//! policy schema. Both parsing (YAML→types) and serialization (types→YAML)
//! use these types, ensuring round-trip fidelity.
