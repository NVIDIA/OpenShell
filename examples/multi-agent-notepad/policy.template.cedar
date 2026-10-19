// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of policy.template.yaml, applied to every sandbox in the
// multi-agent notepad demo. demo.sh replaces __OWNER__, __REPO__, and
// __RUN_ID__ in either file; run it with POLICY_FORMAT=cedar to use this one.
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
    ["/usr/bin/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/auth.openai.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"auth.openai.com:443"
)
when {
    ["/usr/bin/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/chatgpt.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"chatgpt.com:443"
)
when {
    ["/usr/bin/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex/ab.chatgpt.com")
permit (
    principal is Sandbox::Process,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == Sandbox::NetworkEndpoint::"ab.chatgpt.com:443"
)
when {
    ["/usr/bin/codex", "/usr/bin/node"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_aliases.containsAny(["/usr/bin/codex", "/usr/bin/node"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

// network_policies.codex_plugins: git fetches the Codex plugin repository.
// A YAML GET rule also allows HEAD; Cedar lists HEAD explicitly. The `/`
// delimiter keeps `*` within one path segment, as in YAML.
@id("codex_plugins/connect")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"NetworkConnect",
    resource == Sandbox::NetworkEndpoint::"github.com:443"
)
when {
    ["/usr/bin/git", "/usr/lib/git-core/git-remote-http"].contains(context.binary_path)
    || context.ancestors.containsAny(["/usr/bin/git", "/usr/lib/git-core/git-remote-http"])
    || context.binary_aliases.containsAny(["/usr/bin/git", "/usr/lib/git-core/git-remote-http"])
    || context.binary_globs.contains("/usr/lib/node_modules/@openai/**")
};

@id("codex_plugins/rules")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"github.com:443"
)
when {
    (["/usr/bin/git", "/usr/lib/git-core/git-remote-http"].contains(context.binary_path)
     || context.ancestors.containsAny(["/usr/bin/git", "/usr/lib/git-core/git-remote-http"])
     || context.binary_aliases.containsAny(["/usr/bin/git", "/usr/lib/git-core/git-remote-http"])
     || context.binary_globs.contains("/usr/lib/node_modules/@openai/**"))
    && ((["GET", "HEAD"].contains(context.method)
         && context.path like("/openai/plugins.git/info/refs*", "/"))
        || (context.method == "POST"
            && context.path == "/openai/plugins.git/git-upload-pack"))
};

// network_policies.github_memory: curl reads the shared repository and writes
// the notes of this run.
@id("github_memory/connect")
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

@id("github_memory/rules")
permit (
    principal is Sandbox::Process,
    action == Sandbox::Action::"HttpRequest",
    resource == Sandbox::NetworkEndpoint::"api.github.com:443"
)
when {
    (context.binary_path == "/usr/bin/curl"
     || context.ancestors.contains("/usr/bin/curl")
     || context.binary_aliases.contains("/usr/bin/curl"))
    && ((["GET", "HEAD"].contains(context.method)
         && (context.path == "/repos/__OWNER__/__REPO__"
             || context.path == "/repos/__OWNER__/__REPO__/contents/runs/__RUN_ID__"
             || context.path like("/repos/__OWNER__/__REPO__/contents/runs/__RUN_ID__/**", "/")))
        || (context.method == "PUT"
            && context.path like("/repos/__OWNER__/__REPO__/contents/runs/__RUN_ID__/**", "/")))
};
