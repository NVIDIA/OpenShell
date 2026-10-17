// Identity guard
// run_as_user: sandbox / run_as_group: sandbox
// Connections are denied unless the process runs as sandbox:sandbox.
// Placed as a top-level forbid so it cannot be bypassed by any permit.
// Scoped to NetworkConnect: every HttpRequest happens on a connection
// whose CONNECT was already checked, and Landlock grants cannot be
// conditioned on identity.

forbid (principal is Sandbox::Process, action == Sandbox::Action::"NetworkConnect", resource)
unless {
    principal.user  == Sandbox::User::"sandbox"
    && principal.group == Sandbox::Group::"sandbox"
};

// Filesystem: read-only paths
// /usr /lib /proc /dev/urandom /app /etc /var/log

@landlock("best_effort")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"ReadFile",
    resource  is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/var/log"
    || resource in Sandbox::FilesystemPath::"/proc/self"
    || resource in Sandbox::FilesystemPath::"/dev/urandom"   // leaf, not dir
};

// Filesystem: read-write paths
// /sandbox /tmp /dev/null

@landlock("best_effort")
permit (
    principal is Sandbox::Process,
    action    in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource  is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/sandbox"
    || resource in Sandbox::FilesystemPath::"/tmp"
    || resource in Sandbox::FilesystemPath::"/dev/null"      // leaf, not dir
};

// Network: Allow PyPI access so pip can install dependencies
// inside the sandbox
// endpoint: pypi.org:443
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when { context.binary_path == "/sandbox/.venv/bin/python3" };

// Network: Allow PyPI access so pip can install dependencies
// inside the sandbox
// endpoint: files.pythonhosted.org:443
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"files.pythonhosted.org:443"
)
when { context.binary_path == "/sandbox/.venv/bin/python3" };

// Network: NVIDIA API (L7 intercept)
// endpoint: integrate.api.nvidia.com:443
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when { context.binary_path == "/sandbox/.venv/bin/python3" };

// Network: NVIDIA API (L7 per-request enforcement)
// Only the chat completions endpoint may be POSTed to; anything else on
// this already-permitted tunnel is denied at the request level.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when {
    context.binary_path == "/sandbox/.venv/bin/python3"
    && context.method == "POST"
    && context.path == "/v1/chat/completions"
};
