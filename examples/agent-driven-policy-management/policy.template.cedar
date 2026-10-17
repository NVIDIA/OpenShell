// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.template.yaml, the initial policy of the
// agent-driven policy demo. It grants the same access, but the demo itself
// needs the YAML policy: approved proposals are YAML rules merged into the
// sandbox policy, and Cedar policies do not accept merges.
//
// Landlock compatibility (best_effort) and process identity use their
// defaults, as in policy.template.yaml. A YAML binary path also matches an
// ancestor process and a symlink to the binary, so each binary condition
// tests all three. The YAML binary glob `/usr/lib/node_modules/@openai/**`
// also matches an ancestor process; `context.binary_globs` lists the patterns
// that match the calling binary or an ancestor, so the condition tests it
// there.

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

// network_policies.codex: Codex and its Node runtime reach the OpenAI and
// ChatGPT endpoints. Each endpoint is `protocol: rest`, `enforcement:
// enforce`, `access: full`: one policy per endpoint allows the connection and
// every request on it, and naming the endpoint for HttpRequest makes the
// proxy inspect each request.
@id("codex/api.openai.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"api.openai.com:443"
)
when {
    ["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/auth.openai.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"auth.openai.com:443"
)
when {
    ["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/chatgpt.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"chatgpt.com:443"
)
when {
    ["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/ab.chatgpt.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"ab.chatgpt.com:443"
)
when {
    ["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/sandbox/payload/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

// network_policies.github_api_readonly: curl reads api.github.com. The
// `access: read-only` preset allows GET, HEAD, and OPTIONS on every path, so
// writes are denied.
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

// network_policies.github_raw_scoped: curl may GET one bootstrap path on
// raw.githubusercontent.com. A YAML GET rule also allows HEAD; Cedar lists
// HEAD explicitly.
@id("github_raw_scoped/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"raw.githubusercontent.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    || context.ancestors.contains("/usr/bin/curl")
    || context.binary_aliases.contains("/usr/bin/curl")
};

@id("github_raw_scoped/rules")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"raw.githubusercontent.com:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && ["GET", "HEAD"].contains(context.method)
    && context.path == "/github/rest-api-description/main/README.md"
};
