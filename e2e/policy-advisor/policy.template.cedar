// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.template.yaml: read-only REST access to
// api.github.com for curl.
//
// Cedar has no `process` section. policy.template.yaml sets run_as_user and
// run_as_group to `sandbox`; middleware.yaml carries the same identity, and
// test.sh passes it with --middleware. Landlock compatibility uses its
// default, best_effort. The agent-driven proposal loop that test.sh exercises
// merges YAML rules, so it needs the YAML policy.

// filesystem_policy.read_write. Cedar has no include_workdir; /sandbox is the
// default workdir and is listed explicitly.
@id("filesystem/read_write")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/sandbox"
    || resource in Sandbox::FilesystemPath::"/tmp"
    || resource in Sandbox::FilesystemPath::"/dev/null"
};

// filesystem_policy.read_only.
@id("filesystem/read_only")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"ReadFile",
    resource is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/proc"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/var/log"
};

// network_policies.github_api_readonly: curl connects to api.github.com:443.
// A YAML binary path also matches an ancestor process and a symlink to the
// binary, so the condition tests all three.
@id("github_api_readonly/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

// `protocol: rest`, `enforcement: enforce`, `access: read-only`: the preset
// allows GET, HEAD, and OPTIONS on every path. Naming the endpoint in an
// HttpRequest policy makes the proxy inspect each request.
@id("github_api_readonly/read-only")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && ["GET", "HEAD", "OPTIONS"].contains(context.method)
};
