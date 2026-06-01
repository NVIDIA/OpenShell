// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export { OidcRefresher, OpenShellClient } from './index.js'
export type {
  ConnectOptions,
  ExecOptions,
  ExecResult,
  Health,
  JsRefreshedToken,
  ListOptions,
  SandboxRef,
  SandboxSpec,
} from './index.js'

/**
 * Extract the SDK error code from a thrown error.
 *
 * The native binding prefixes every error message with `[code] ` where
 * `code` is one of: `invalid_config`, `tls`, `connect`, `auth`, `io`,
 * `not_found`, `already_exists`, `rpc`. Returns `null` when the prefix is
 * missing (the error wasn't thrown by this binding).
 */
export declare function errorCode(err: unknown): string | null
