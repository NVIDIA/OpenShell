// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Public API surface for @nvidia/openshell-sdk.
//
export type {
  ConnectOptions,
  DeleteOptions,
  DeletionOutcome,
  DeletionResult,
  EffectiveSettingView,
  ExecExitEvent,
  ExecInteractiveOptions,
  ExecInteractiveSession,
  ExecInteractiveSessionControl,
  ExecOptions,
  ExecResult,
  ExecStreamChunk,
  ExecStreamEvent,
  ForwardHandle,
  ForwardOptions,
  Health,
  HealthStatus,
  ListOptions,
  Page,
  PolicyDocument,
  PolicySourceName,
  ProviderChange,
  ProviderChangeOptions,
  ProviderRef,
  SandboxConfig,
  SandboxFromTemplateSpec,
  SandboxPhaseName,
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
  ServiceExposure,
  SetPolicyOptions,
  SettingScopeName,
  SettingValue,
  SshSession,
  UpdateConfigResult,
  WaitDeletedOptions,
  WaitOptions,
  WorkspaceListScope,
} from './client.js';
export {
  errorCode,
  OpenShellClient,
  Pager,
  SandboxClient,
  SandboxTemplateClient,
  validatePolicyDocument,
} from './client.js';
export type { ErrorInfo, FieldViolation, SdkErrorCode } from './errors.js';
export { fromConnect, SdkError } from './errors.js';
export type { ClientCredentialsOptions, OidcTokenProvider } from './oidc.js';
export { clientCredentials } from './oidc.js';
