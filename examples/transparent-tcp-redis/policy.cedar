// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml: any binary may open native TCP connections to
// redis.openshell.demo:6379 when the host resolves to a private address.
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

// network_policies.redis. `protocol: tcp` is @transport("tcp"): the
// connection is plain L4 traffic, reached through policy DNS. The binary glob
// `/**` matches every binary. `allowed_ips` is the destination_ip condition:
// every address the host resolves to must lie in one of the ranges.
@id("redis/connect")
@transport("tcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"redis.openshell.demo:6379"
)
when {
    context.binary_path like("/**", "/")
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.0.0/8"))
        || context.destination_ip.isInRange(ip("172.16.0.0/12"))
        || context.destination_ip.isInRange(ip("192.168.0.0/16")))
};
