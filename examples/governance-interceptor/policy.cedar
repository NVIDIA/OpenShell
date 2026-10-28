// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml: curl has full REST access to
// api-1.example.com. The interceptor injects policy.yaml, so this file is a
// reference for creating a Cedar sandbox directly:
//
//   openshell sandbox create --policy policy.cedar
//
// Landlock compatibility (best_effort) and process identity use their
// defaults, as in policy.yaml.

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

// network_policies.my_api: curl connects to api-1.example.com:443. A YAML
// binary path also matches an ancestor process and a symlink to the binary,
// so the condition tests all three.
@id("my_api/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"api-1.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

// `protocol: rest`, `enforcement: enforce`, `access: full`: every method on
// every path. Naming the endpoint in an HttpRequest policy makes the proxy
// inspect each request.
@id("my_api/full")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api-1.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};
