// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy-template.yaml, used when POLICY_FORMAT=cedar.
// render-policy.py substitutes $${host}, $${port}, and $${path} (a quoted
// string) from the conformance server URL. The MCP revision and body limit
// are endpoint settings, rendered from middleware-template.yaml.
//
// Cedar has no `process` section; the client runs as `sandbox` like the YAML
// policy because middleware-template.yaml carries the process identity.
// Landlock compatibility uses its default, best_effort. A YAML binary path also
// matches an ancestor process and a symlink to the binary, so each binary
// condition tests all three. The YAML binary glob
// `/opt/mcp-conformance/node_modules/.bin/*` also matches an ancestor
// process; `context.binary_globs` lists the patterns that match the calling
// binary or an ancestor, so the condition tests it there.

// filesystem_policy.read_write. Cedar has no include_workdir; the client
// image's workdir, /opt/mcp-conformance, is listed explicitly.
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
    || resource in Sandbox::FilesystemPath::"/home/sandbox"
    || resource in Sandbox::FilesystemPath::"/opt/mcp-conformance"
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
    || resource in Sandbox::FilesystemPath::"/lib64"
    || resource in Sandbox::FilesystemPath::"/proc"
    || resource in Sandbox::FilesystemPath::"/sys"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/opt"
    || resource in Sandbox::FilesystemPath::"/var/log"
};

// network_policies.mcp_conformance: the client connects to the conformance
// server. `allowed_ips` is the destination_ip condition: every address the
// host resolves to must lie in one of the private ranges.
@id("mcp_conformance/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"${host}:${port}"
)
when {
    (["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"].contains(context.binary_path)
     || context.ancestors.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_aliases.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_globs.contains("/opt/mcp-conformance/node_modules/.bin/*"))
    && context has destination_ip
    && (context.destination_ip.isInRange(ip("10.0.0.0/8"))
        || context.destination_ip.isInRange(ip("172.16.0.0/12"))
        || context.destination_ip.isInRange(ip("192.168.0.0/16"))
        || context.destination_ip.isInRange(ip("fc00::/7")))
};

// `protocol: mcp`, `enforcement: enforce`, `mcp.allow_all_known_mcp_methods`:
// every core method of the selected MCP revision is allowed, and extension
// methods are not.
@id("mcp_conformance/methods")
@path(${path})
@protocol("mcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"${host}:${port}"
)
when {
    (["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"].contains(context.binary_path)
     || context.ancestors.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_aliases.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_globs.contains("/opt/mcp-conformance/node_modules/.bin/*"))
    && context.path == ${path}
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
};

// An MCP endpoint in YAML also allows the receive stream and client response
// frames, such as answers to elicitation/create; Cedar permits them
// explicitly.
@id("mcp_conformance/streams")
@path(${path})
@protocol("mcp")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"${host}:${port}"
)
when {
    (["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"].contains(context.binary_path)
     || context.ancestors.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_aliases.containsAny(["/bin/sh", "/usr/bin/env", "/usr/local/bin/node", "/usr/bin/node"])
     || context.binary_globs.contains("/opt/mcp-conformance/node_modules/.bin/*"))
    && context.path == ${path}
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
