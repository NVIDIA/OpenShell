// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Public API surface for @nvidia/openshell-sdk.
//
export type {
  ConnectOptions,
  CPUResourceRequirements,
  DeleteOptions,
  DeletionOutcome,
  DeletionResult,
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
  GPUResourceRequirements,
  Health,
  HealthStatus,
  ListOptions,
  MemoryResourceRequirements,
  Page,
  PolicySourceName,
  ProviderChange,
  ProviderChangeOptions,
  ProviderRef,
  ResourceRequirements,
  SandboxConfig,
  SandboxFromTemplateSpec,
  SandboxPhaseName,
  SandboxPolicy,
  SandboxRef,
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
  WaitDeletedOptions,
  WaitOptions,
  WorkspaceListScope,
} from './client.js';
export { errorCode, OpenShellClient, Pager, SandboxClient, SandboxTemplateClient } from './client.js';
export type { ErrorInfo, FieldViolation, SdkErrorCode } from './errors.js';
export { fromConnect, SdkError } from './errors.js';
export type { ClientCredentialsOptions, OidcTokenProvider } from './oidc.js';
export { clientCredentials } from './oidc.js';
