// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The driver side of the contract: producing what a driver hands over.
//!
//! Behind the `write` feature, so that readers do not build the certificate
//! generation code.

mod tls;

pub use tls::generate_sandbox_tls_material;
