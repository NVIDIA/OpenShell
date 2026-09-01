<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Git commit signing supervisor middleware prototype

This example tests whether an operator-run OpenShell supervisor middleware can sign commits without mounting a signing key into the sandbox. It uses the streaming `HttpRequestPreCredentials.Evaluate` API to intercept Git smart-HTTP `git-receive-pack` requests after network policy admission and before provider credential injection. The service selects `WHOLE_BODY_BYTES`, rewrites the pushed commit objects with SSH signatures, and returns a transform action for the single request body unit.

The sandbox sees neither the private key nor the signature operation. Its Git client creates ordinary unsigned commits and pushes over HTTPS.

## What the prototype does

For each direct branch update in a push, the service:

1. Derives a bounded `github.com/<org>/<repo>.git` upstream URL from the policy-admitted request target.
2. Shallow-fetches the upstream default branch and updated branch tips into a temporary bare repository. This supplies bases omitted from normal thin pushes.
3. Decodes the receive-pack command pkt-lines and packfile, then walks only commits that are not already reachable from the fetched upstream refs.
4. Removes any existing commit signature and signs the exact rewritten commit payload with `ssh-keygen -Y sign -n git`.
5. Rewrites parent object IDs, creates a replacement thin pack, and substitutes the new branch-tip object ID in the receive-pack command.
6. Returns the modified body to the supervisor, which forwards it with the sandbox's normal GitHub credential.

The signing key is a service startup argument, not policy-controlled middleware configuration. A sandbox cannot select an arbitrary host file to sign with.

## Build and test

The test constructs a two-commit push, transforms it, sends the replacement request through Git's real `receive-pack --stateless-rpc`, checks the updated branch tip, and verifies both SSH signatures with `git verify-commit`.

```shell
cargo test --manifest-path examples/supervisor-middleware-git-signing/Cargo.toml
```

The example requires `git` and `ssh-keygen` on the host.

## Run the service

Use an SSH key that is also registered as a signing key with the Git forge. GitHub distinguishes signing keys from authentication keys even when the same public key material is used.

```shell
cargo run \
  --manifest-path examples/supervisor-middleware-git-signing/Cargo.toml \
  -- \
  --bind 0.0.0.0:50051 \
  --signing-key "$HOME/.ssh/id_ed25519"
```

Register the local service in `gateway.toml`. A container-backed gateway can reach a host service through `host.openshell.internal`; a host-native gateway can use `127.0.0.1`.

```toml
[[openshell.supervisor.middleware]]
name = "local-git-signer"
grpc_endpoint = "http://host.openshell.internal:50051"
max_payload_bytes = 4194304
timeout = "30s"
```

Restart the gateway after adding the static registration, then replace `<org>` and `<repo>` in [policy.yaml](policy.yaml) and create a sandbox with that policy. Keep the endpoint on `fail_closed`: an unsigned push is preferable to reject rather than silently forward when signing fails.

The service skips unrelated GitHub HTTP requests during preflight. It inspects only `POST` requests whose path ends in `/git-receive-pack` and whose content type is `application/x-git-receive-pack-request`. This prototype accepts only validated HTTPS targets on `github.com:443` with a two-segment repository path.

The signer implements `SupervisorMiddleware` for discovery and configuration validation, and serves `HttpRequestPreCredentials` alongside it. It deliberately returns `UNIMPLEMENTED` from the legacy unary `EvaluateHttpRequest` method. This makes the example fail if OpenShell silently falls back to the old request API.

## Prototype limits

- The experiment still retains the admitted request body in the relay before opening middleware streams. The new API streams between OpenShell and the service, but it does not yet remove the relay's 4 MiB request buffer. Both the incoming push and expanded replacement pack must fit that limit.
- The implementation supports SHA-1 repositories and direct `refs/heads/*` updates. It rejects SHA-256 repositories, annotated-tag pushes, push certificates, and other ref types.
- Each push shallow-fetches upstream objects before signing. The host must be able to reach the repository, and private repositories need a non-interactive Git credential helper available to the local middleware user. A production design should use a bounded object cache and explicit credential plumbing.
- The service shells out to the host's `git` and `ssh-keygen`; it needs resource limits, concurrency limits, timeouts, and hardened subprocess execution before production use.
- Rewriting commit object IDs means the sandbox's local branch still points to the unsigned commit after a successful push. A subsequent fetch updates the remote-tracking ref, but the local branch must be reconciled with the rewritten history. This is the largest workflow issue for transparent push-time signing.
- The example has unit-level protocol coverage, not a live GitHub push. Test against a disposable repository before using a real signing key.

These constraints make the approach viable as a proof of concept, but not yet transparent enough for general production pushes. A first-class commit-signing operation invoked before Git creates the final local object would avoid the local/remote object-ID split while still keeping the private key outside the sandbox.
