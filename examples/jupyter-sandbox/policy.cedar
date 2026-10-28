// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml: filesystem access for the notebook server and
// no outbound network access. The Jupyter service is exposed inbound through
// the gateway, which a sandbox policy does not govern.
//
// Cedar has no `process` section. policy.yaml sets run_as_user `jovyan` and
// run_as_group `users`; a Cedar sandbox uses the identity the compute driver
// selects, which for Docker and Podman is the image user, `jovyan`. Landlock
// compatibility uses its default, best_effort.

// filesystem_policy.read_write. Cedar has no include_workdir; the image's
// workdir, /home/jovyan, is listed explicitly.
@id("filesystem/read_write")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/home/jovyan"
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
    resource in Sandbox::FilesystemPath::"/opt"
    || resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/proc"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/var/log"
};
