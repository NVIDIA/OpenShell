// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml, the gator sandbox policy. It grants
// filesystem access and no network access: without a NetworkConnect permit,
// Cedar denies every connection, like the empty network_policies map.
//
// Cedar has no `process` section. policy.yaml sets run_as_user and
// run_as_group to `sandbox`; middleware.yaml carries the same identity for
// `--middleware`. Landlock compatibility uses its default, best_effort. The
// gator image bakes policy.yaml into /etc/openshell/policy.yaml, which must
// be YAML; pass this file with `openshell sandbox create --policy` and
// middleware.yaml with `--middleware` instead. Gator relies on agent policy
// proposals, which merge YAML rules, so they do not apply to a Cedar sandbox.

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
