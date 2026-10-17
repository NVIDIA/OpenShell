// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.yaml. The content-guard middleware is configuration,
// not policy, so it lives in middleware.yaml:
//
//   openshell sandbox create --policy policy.cedar --middleware middleware.yaml
//
// policy.yaml has no filesystem_policy, so the supervisor grants the workdir
// and its baseline runtime paths. A Cedar sandbox gets the same baseline, and
// this policy grants the workdir, /sandbox.
//
// The YAML endpoints set no `enforcement`, which defaults to audit: a request
// the rules deny is logged and forwarded. Every HttpRequest policy below is
// therefore @enforcement("audit"). A YAML binary path also matches an
// ancestor process and a symlink to the binary, so each condition tests all
// three.

@id("filesystem/workdir")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource in Sandbox::FilesystemPath::"/sandbox"
);

// network_policies.httpbin.
@id("httpbin/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"httpbin.org:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

@id("httpbin/rules")
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"httpbin.org:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && context.method == "POST"
    && context.path == "/anything"
};

// network_policies.httpbingo.
@id("httpbingo/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"httpbingo.org:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

@id("httpbingo/rules")
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"httpbingo.org:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && context.method == "POST"
    && context.path == "/anything"
};

// network_policies.guard-responses. A YAML GET rule also allows HEAD; Cedar
// lists HEAD explicitly.
@id("guard-responses/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"host.openshell.internal:18081"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

@id("guard-responses/rules")
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"host.openshell.internal:18081"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
    && ["/clean", "/sensitive"].contains(context.path)
};
