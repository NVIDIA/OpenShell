// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of sandbox-policy.yaml.
//
// sandbox-policy.yaml has no filesystem_policy, so the supervisor grants the
// workdir and its baseline runtime paths. A Cedar sandbox gets the same
// baseline because this policy has a NetworkConnect permit, and this policy
// grants the workdir, /sandbox.
//
// The YAML endpoint api.anthropic.com:443 lists no binaries, so it lets no
// process connect: a YAML binary list must match the calling binary. The
// permit below is its translation: it names the endpoint, which makes
// api.anthropic.com resolvable through policy DNS as in YAML, and admits no
// binary. Providers attached to a Cedar sandbox supply credentials but grant
// no access, and the Policy Advisor approval flow merges YAML rules, so to
// let an agent reach the API, add its binary to the condition, for example
// `context.binary_path == "/usr/local/bin/claude"`.

@id("anthropic/api.anthropic.com:443")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"api.anthropic.com:443"
)
when { false };

@id("filesystem/workdir")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource in Sandbox::FilesystemPath::"/sandbox"
);
