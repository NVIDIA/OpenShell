// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Public API surface for @nvidia/openshell-sdk.
//
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
  SandboxFromTemplateSpec,
  SandboxPhaseName,
  SandboxPolicy,
  SandboxRef,
  SandboxResources,
  SandboxServiceLevel,
  SandboxSpec,
  SandboxStartup,
  SandboxTemplateListOptions,
  SandboxTemplateWorkspaceOptions,
  SandboxWorkloadConfig,
  SandboxWorkloadTemplate,
  SandboxWorkloadTemplateProvenance,
  SandboxWorkloadTemplateSpec,
  SetPolicyOptions,
  SettingScopeName,
  SettingValue,
  SshSession,
  UpdateConfigResult,
  WaitOptions,
} from './client.js';
export { errorCode, OpenShellClient, SandboxClient, SandboxTemplateClient } from './client.js';
export type { SdkErrorCode } from './errors.js';
export { SdkError } from './errors.js';
export type { ClientCredentialsOptions, OidcTokenProvider } from './oidc.js';
export { clientCredentials } from './oidc.js';
