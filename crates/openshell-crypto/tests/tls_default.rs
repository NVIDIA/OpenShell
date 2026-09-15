// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn default_initialization_is_idempotent() {
    let first = openshell_crypto::tls::ensure_default_provider();
    let second = openshell_crypto::tls::ensure_default_provider();
    assert!(std::sync::Arc::ptr_eq(first, second));
    let expected = openshell_crypto::tls::provider();
    assert_eq!(first.cipher_suites, expected.cipher_suites);
    assert_eq!(
        first.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
        expected
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn repeated_context_selection_accepts_only_the_same_context() {
    let context = openshell_crypto::default_context().clone();
    openshell_crypto::install_default_context(context.clone()).unwrap();
    openshell_crypto::install_default_context(context).unwrap();
}
