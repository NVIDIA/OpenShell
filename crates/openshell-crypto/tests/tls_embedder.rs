// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn library_initialization_preserves_embedder_policy() {
    // Separate test executable: process-default state cannot leak from other tests.
    let mut host = openshell_crypto::tls::provider();
    host.cipher_suites.truncate(1);
    host.install_default().unwrap();
    let installed = openshell_crypto::tls::ensure_default_provider();
    assert_eq!(installed.cipher_suites.len(), 1);
    assert!(openshell_crypto::tls::provider().cipher_suites.len() > 1);
}
