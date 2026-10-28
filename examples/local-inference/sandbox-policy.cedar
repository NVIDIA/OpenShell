// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of sandbox-policy.yaml with the nvidia-inference provider
// attached: Python may reach PyPI so pip can install dependencies, and the
// NVIDIA API Catalog endpoint. Landlock compatibility (best_effort) and
// process identity use their defaults, as in sandbox-policy.yaml.

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
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/var/log"
    || resource in Sandbox::FilesystemPath::"/proc/self"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
};

// network_policies.pypi: the endpoints have no protocol, so connections are
// plain L4 and no HttpRequest policy names them. A YAML binary path also
// matches an ancestor process and a symlink to the binary, so each condition
// tests all three.
@id("pypi/connect/pypi.org")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when {
    context.binary_path == "/usr/bin/python3.13"
    || context.ancestors.contains("/usr/bin/python3.13")
    || context.binary_aliases.contains("/usr/bin/python3.13")
};

@id("pypi/connect/files.pythonhosted.org")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"files.pythonhosted.org:443"
)
when {
    context.binary_path == "/usr/bin/python3.13"
    || context.ancestors.contains("/usr/bin/python3.13")
    || context.binary_aliases.contains("/usr/bin/python3.13")
};

// The NVIDIA endpoint. With YAML, the attached nvidia-inference provider
// (nvidia-inference.yaml) adds this endpoint to the network policy. A Cedar
// sandbox's providers supply credentials but grant no access, so the policy
// grants what the profile grants: its binaries may connect, and the
// `access: read-write` preset allows GET, HEAD, OPTIONS, POST, PUT, and PATCH.
// A credentialed endpoint must be inspected, which the HttpRequest policy
// does. The profile's binary glob `/sandbox/.venv/**` also matches an
// ancestor process in YAML; `context.binary_globs` lists the patterns that
// match the calling binary or an ancestor, so the condition tests it there.
@id("nvidia-inference/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when {
    ["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"])
    || context.binary_aliases.containsAny(["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"])
    || context.binary_globs.contains("/sandbox/.venv/**")
};

@id("nvidia-inference/read-write")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when {
    (["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"].contains(context.binary_path)
     || context.ancestors.containsAny(["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"])
     || context.binary_aliases.containsAny(["/usr/bin/python3", "/usr/bin/python3.13", "/usr/local/bin/python"])
     || context.binary_globs.contains("/sandbox/.venv/**"))
    && ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"].contains(context.method)
};
