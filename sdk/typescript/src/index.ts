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
  ExecExitEvent,
  ExecInteractiveOptions,
  ExecInteractiveSession,
  ExecOptions,
  ExecResult,
  ExecStreamChunk,
  ExecStreamEvent,
  ForwardHandle,
  ForwardOptions,
  Health,
  HealthStatus,
  ListOptions,
  PolicySourceName,
  ProviderChange,
  ProviderChangeOptions,
  ProviderRef,
  SandboxConfig,
  SandboxPhaseName,
  SandboxPolicy,
  SandboxRef,
  SandboxSpec,
  SetPolicyOptions,
  SettingScopeName,
  SettingValue,
  SshSession,
  UpdateConfigResult,
  WaitOptions,
} from './client.js';
export { errorCode, OpenShellClient, SandboxClient } from './client.js';
export type { SdkErrorCode } from './errors.js';
export { SdkError } from './errors.js';
