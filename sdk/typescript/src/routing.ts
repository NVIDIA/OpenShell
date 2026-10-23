// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Metadata that lets an edge proxy send a sandbox's long-lived calls straight
// to the gateway replica holding its supervisor session.

import { Code, ConnectError } from '@connectrpc/connect';

export const OWNER_REPLICA_HEADER = 'x-openshell-owner';
export const OWNER_REQUEST_HEADER = 'x-openshell-want-owner';
const ROUTE_REPLICA_HEADER = 'x-openshell-replica';

export interface RoutedAttempt {
  headers?: Record<string, string>;
  onHeader: () => void;
  // Resolves true once the response headers arrive, false if the attempt fails first.
  ready: Promise<boolean>;
}

// Envoy Gateway answers a replica route with no ready endpoints with
// UNAVAILABLE and no message; gateway errors always carry one.
export function retryUnrouted(error: unknown): boolean {
  if (!(error instanceof ConnectError) || error.code !== Code.Unavailable) return false;
  const message = error.rawMessage;
  return message === '' || message.includes('no healthy upstream') || message.includes('connection failure');
}

// Open a stream tagged with the owner replica, and once more untagged when the
// proxy rejects it before sending headers because the owner's route has no
// ready endpoints. A stale owner is safe: any replica relays the call.
export async function* routedStream<T>(
  owner: string | undefined,
  open: (attempt: RoutedAttempt) => AsyncIterable<T>,
): AsyncGenerator<T, void, void> {
  let replica = owner;
  for (;;) {
    let headersSeen = !replica;
    let settle!: (ok: boolean) => void;
    const ready = new Promise<boolean>((resolve) => {
      settle = resolve;
    });
    if (headersSeen) settle(true);
    const onHeader = (): void => {
      headersSeen = true;
      settle(true);
    };
    try {
      const headers = replica ? { [ROUTE_REPLICA_HEADER]: replica } : undefined;
      yield* open({ headers, onHeader, ready });
      return;
    } catch (e) {
      if (headersSeen || !retryUnrouted(e)) throw e;
      replica = undefined;
    } finally {
      settle(false);
    }
  }
}

// Request frames for one attempt: `first`, then `rest` once the attempt is
// ready, so a retried attempt only has to resend `first`.
export async function* heldUntilReady<T>(first: T, rest: AsyncIterable<T>, ready: Promise<boolean>): AsyncGenerator<T> {
  yield first;
  if (await ready) yield* rest;
}
