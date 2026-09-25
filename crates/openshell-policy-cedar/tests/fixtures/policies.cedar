// Identity guard
// run_as_user: sandbox / run_as_group: sandbox
// All actions are denied unless the process runs as sandbox:sandbox.
// Placed as a top-level forbid so it cannot be bypassed by any permit.

forbid (principal is Sandbox::Process, action, resource)
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
    || resource == Sandbox::FilesystemPath::"/dev/urandom"   // leaf, not dir
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
    || resource == Sandbox::FilesystemPath::"/dev/null"      // leaf, not dir
};

// Network: Allow PyPI access so pip can install dependencies
// inside the sandbox
// endpoint: pypi.org:443 (REST, enforce, read-only)
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
    && context.method == "GET"          // access: read-only → GET only
};

// Network: Allow PyPI access so pip can install dependencies
// inside the sandbox
// endpoint: files.pythonhosted.org:443 (REST, enforce, read-only)
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"files.pythonhosted.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
    && context.method == "GET"          // access: read-only → GET only
};

// Network: NVIDIA API (L7 intercept)
// endpoint: integrate.api.nvidia.com:443 (REST, enforce, read-only)
// binary:   /sandbox/.venv/bin/python3.

@enforcement("enforce")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
    && (context.method == "GET"
        || context.method == "POST")
};
