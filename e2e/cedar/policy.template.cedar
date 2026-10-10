// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar policy for the Cedar e2e suite. test.sh replaces __HOST__, __PORT__,
// and __PREFIX__ with the upstream echo service's host, port, and path prefix.

// Filesystem: Landlock grants. The supervisor adds its baseline paths
// (/usr, /lib, /etc, /proc, /tmp, ...) on top of these, so the test only
// asserts on paths outside that baseline.
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource in Sandbox::FilesystemPath::"/sandbox"
);

permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"ReadFile",
    resource in Sandbox::FilesystemPath::"/opt"
);

// Network: only curl may connect to the upstream.
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"__HOST__:__PORT__"
)
when { context.binary_path == "/usr/bin/curl" };

// Network: curl may reach any single-label subdomain of github.com. The
// delimited host glob also makes those hosts resolvable through policy DNS.
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource is Sandbox::NetworkEndpoint
)
when {
    resource.host like("*.github.com", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};

// Requests: GET one path segment under /allowed/, and POST only to
// /allowed/echo. The `/` delimiter keeps `*` within one segment.
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"__HOST__:__PORT__"
)
when {
    (context.method == "GET" && context.path like("__PREFIX__/allowed/*", "/"))
    || (context.method == "POST" && context.path == "__PREFIX__/allowed/echo")
};

// A forbid overrides the permit above.
forbid (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"__HOST__:__PORT__"
)
when { context.path == "__PREFIX__/allowed/secret" };

// A staged restriction: audit-only, so it is logged but never denies.
@enforcement("audit")
@id("staged-no-staged-path")
forbid (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"__HOST__:__PORT__"
)
when { context.path == "__PREFIX__/allowed/staged" };
