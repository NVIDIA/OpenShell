// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Separate test executable so another test cannot initialize the global context.
#[test]
#[should_panic(expected = "install a crypto context before use")]
fn crypto_use_without_a_context_fails_closed() {
    let _ = openshell_sdk::oidc::http_client(false);
}
