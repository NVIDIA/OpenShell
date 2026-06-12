<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy Source Example

This example includes a small governed policy and provider profile bundle. It
can be loaded directly from the filesystem or served over local gRPC.

```text
bundle/
  policies/
    default.yaml
    gitlab.yaml
    github.yaml
  providers/
    example.yaml
```

The source service listens on a Unix domain socket and implements
`openshell.policy_source.v1.PolicySource`:

```proto
service PolicySource {
  rpc ListPolicies(ListDocumentsRequest) returns (ListDocumentsResponse);
  rpc GetPolicy(GetDocumentRequest) returns (Document);
  rpc ListProviders(ListDocumentsRequest) returns (ListDocumentsResponse);
  rpc GetProvider(GetDocumentRequest) returns (Document);
}
```

Configure the gateway with:

```toml
[openshell.gateway.policies]
location = "grpc+unix:///tmp/openshell-policy-source.sock"
default_policy = "default"
```

Or load the bundle directly from the filesystem:

```toml
[openshell.gateway.policies]
location = "./examples/policy-source/bundle"
default_policy = "default"
```

`GetPolicy("default")` returns an OpenShell sandbox policy YAML document.
`GetProvider("<name>")` returns a Providers v2 provider profile YAML document.
Getter responses contain only `bytes document = 1`; the gateway parses those
bytes as UTF-8 YAML and stores a SHA-256 digest over the exact payload.

Run the smoke test:

```shell
examples/policy-source/smoke.sh
```

The script builds `policy-source-server` and `policy-source-check`, creates a
temporary source root, adds `default`, `gitlab`, and `github` policy documents,
starts the Unix-socket gRPC server, and verifies those policies through the
gRPC API.

Run the server directly:

```shell
cargo run -p openshell-policy-source-example --bin policy-source-server -- \
  --socket /tmp/openshell-policy-source.sock \
  --root examples/policy-source/bundle
```

The example gateway TOML files are `gateway-grpc.toml` and
`gateway-filesystem.toml`.
