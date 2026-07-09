// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Public API surface for openshell-sdk.
//
// OidcRefresher (single-flight OIDC refresh) is intentionally not yet exported.
// It is the one piece of genuinely shared, cross-language behavior; it will be
// added alongside a conformance suite that pins it byte-identical across the
// TypeScript, Python, and Go SDKs.

export { OpenShellClient, SandboxClient, errorCode } from './client.js'
export type {
  ConnectOptions,
  ExecOptions,
  ExecResult,
  Health,
  ListOptions,
  SandboxRef,
  SandboxSpec,
} from './client.js'
