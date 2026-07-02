// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Error taxonomy — every thrown error message is prefixed with `[code] ` so
// callers can discriminate with errorCode(). This mirrors the shape the (now
// retired) napi binding exposed, kept stable so consumers migrating off it see
// an identical contract.

import { Code, ConnectError } from '@connectrpc/connect'

export type SdkErrorCode =
  | 'invalid_config'
  | 'tls'
  | 'connect'
  | 'auth'
  | 'io'
  | 'not_found'
  | 'already_exists'
  | 'rpc'

export class SdkError extends Error {
  readonly code: SdkErrorCode
  constructor(code: SdkErrorCode, message: string) {
    // Format `[code] message` so errorCode() can recover the code from any Error.
    super(`[${code}] ${message}`)
    this.name = 'SdkError'
    this.code = code
  }
}

// Map a gRPC status (surfaced by connect-es as ConnectError) onto our codes.
export function fromConnect(err: unknown): SdkError {
  const ce = ConnectError.from(err)
  switch (ce.code) {
    case Code.NotFound:
      return new SdkError('not_found', ce.rawMessage)
    case Code.AlreadyExists:
      return new SdkError('already_exists', ce.rawMessage)
    case Code.InvalidArgument:
      return new SdkError('invalid_config', ce.rawMessage)
    case Code.Unauthenticated:
    case Code.PermissionDenied:
      return new SdkError('auth', ce.rawMessage)
    default:
      return new SdkError('rpc', ce.rawMessage)
  }
}

// Extract the `[code]` prefix from any error message.
export function errorCode(err: unknown): string | null {
  const msg = err instanceof Error ? err.message : String(err)
  const m = /^\[([a-z_]+)\]/.exec(msg)
  return m ? m[1] : null
}
