// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml: curl may read from the GitHub REST API, and
// POST, PUT, PATCH, and DELETE are blocked.
//
//   openshell sandbox create --name demo --policy policy.cedar
//
// A Cedar sandbox stays Cedar for its lifetime, and `openshell policy update`
// does not merge into a Cedar policy. Replace it with `openshell policy set`.
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
    resource in Sandbox::FilesystemPath::"/bin"
    || resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/proc"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/var/log"
};

// network_policies.github_api: curl connects to api.github.com:443. A YAML
// binary path also matches an ancestor process and a symlink to the binary,
// so the condition tests all three.
@id("github_api/connect")
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
@id("github_api/read-only")
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
