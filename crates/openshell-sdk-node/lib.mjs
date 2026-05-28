// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// ESM facade over the auto-generated CommonJS index.
//
// Re-exports the napi-generated classes and adds the `errorCode` helper,
// which parses the `[code] message` prefix the binding uses to surface the
// SDK's discriminable error kind. The auto-generated `index.js`/`index.d.ts`
// pair from napi-rs is left untouched so the build matrix stays cookie-cutter.

import nativeBinding from './index.js'

const { OpenShellClient, OidcRefresher } = nativeBinding

export { OpenShellClient, OidcRefresher }

/**
 * Extract the SDK error code from a thrown error.
 *
 * The native binding prefixes every error message with `[code] ` where
 * `code` is one of: `invalid_config`, `tls`, `connect`, `auth`, `io`,
 * `not_found`, `already_exists`, `rpc`. Returns `null` when the prefix is
 * missing (the error wasn't thrown by this binding).
 *
 * @param {unknown} err
 * @returns {string | null}
 */
export function errorCode(err) {
  if (!err || typeof err.message !== 'string') return null
  const match = err.message.match(/^\[([^\]]+)\]/)
  return match ? match[1] : null
}
