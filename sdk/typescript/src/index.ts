// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Public API surface for @nvidia/openshell-sdk.
//
// OidcRefresher (single-flight OIDC refresh) is intentionally not yet exported.
// It is the one piece of genuinely shared, cross-language behavior; it will be
// added alongside a conformance suite that pins it byte-identical across the
// TypeScript, Python, and Go SDKs.

export type {
  ConnectOptions,
  EffectiveSettingView,
  ExecInteractiveOptions,
  ExecInteractiveSession,
  ExecOptions,
  ExecResult,
  ExecStreamChunk,
  ForwardHandle,
  ForwardOptions,
  Health,
  ListOptions,
  ProviderChange,
  ProviderChangeOptions,
  ProviderRef,
  SandboxConfig,
  SandboxPolicy,
  SandboxRef,
  SandboxSpec,
  SetPolicyOptions,
  SettingValue,
  SshSession,
  UpdateConfigResult,
} from './client.js';
export { errorCode, OpenShellClient, SandboxClient } from './client.js';
