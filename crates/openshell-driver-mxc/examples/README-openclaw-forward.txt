OpenShell MXC - OpenClaw + dynamic forward test (both backends)
=======================================================================

WHAT THIS PROVES
  The full path for reaching a service inside an MXC sandbox that has NO
  in-sandbox supervisor process. This forwarding test uses the default network
  mode; MXC 1.0 proxy-peer mode is egress-only and rejects dynamic forwarding:
    gateway -> MXC driver -> ProcessContainer OR isolation_session sandbox
      -> openshell-supervisor-relay launches OpenClaw's gateway inside it,
         with no relay awareness in OpenClaw itself
      -> `openshell forward service --target-port 18889` opens a fresh,
         on-demand authenticated relay for THIS call only (nothing pre-declared
         in the config beyond the startup liveness port; the relay is torn
         down when the forward ends)
      -> a real OpenClaw client on the HOST, talking only through that
         forwarded port, authenticates with a token and gets a real
         "ok: true" health response.

  Pass -Backend process_container (default) or -Backend isolation_session.
  Both exercise the exact same dynamic-forward/control-channel code path in
  the driver -- only the gateway config differs (mxc-openclaw-gateway.toml
  vs mxc-openclaw-isolation.toml). isolation_session is simpler to configure:
  it merges the per-sandbox environment onto the inherited host environment rather than
  replacing it, so none of ProcessContainer's pc_minimal_env / LOCALAPPDATA
  workaround is needed -- see mxc-openclaw-isolation.toml's own comments for
  what else differs (ProcessContainer-only fields it ignores entirely).

PREREQUISITES (on this test box)
  - An ELEVATED (Administrator) PowerShell session may be required for
    -Backend process_container on hosts whose probe selects the
    "AppContainer + DACL" isolation tier. The runner must update ACLs on the
    staged files. A directory owned by an
    earlier elevated run can also require ownership repair before a
    non-elevated rerun. -Backend isolation_session does not use the proxy peer.
  - wxc-exec.exe present (default expected: C:\mxc-kit\bin\wxc-exec.exe).
    Use a standalone copy in a regular directory, not a copy inside an
    installed MSIX or WindowsApps package directory. If CreateSandbox reports
    "wxc-exec spawn failed: Access is denied. (os error 5)", check this path.
  - Before the first process_container run, check the selected isolation tier
    and host-preparation warnings in PowerShell:
      & "C:\path\to\wxc-exec.exe" --probe
    Only if the probe selects AppContainer + DACL (appcontainer-dacl) and
    recommends prepare-system-drive, obtain wxc-host-prep.exe from the MXC
    binaries distribution and run this once in elevated PowerShell:
      & "C:\path\to\wxc-host-prep.exe" prepare-system-drive
    BaseContainer and AppContainer + BFS do not require this preparation.
    The persistent, host-wide ACL change grants the AppContainer well-known
    SIDs metadata access to the system-drive root only; it does not grant
    directory listing or write access, or change descendant ACLs.
    If wxc-exec starts but the agent exits with "wxc-exec stderr: Access is
    denied." or exit code 1, check the probe warnings before changing host
    ACLs; these errors alone do not identify missing host preparation.
    For verification, other host prerequisites, and rollback, see:
      https://github.com/microsoft/mxc/blob/main/docs/host-prep.md
  - process_container or isolation_session backend live (whichever -Backend
    you pass)
  - Your own OpenClaw install: a node.exe binary + the openclaw npm package
    (the directory containing openclaw.mjs and its own node_modules).
    Neither ships in this package -- point the script at your existing
    install with -NodeExePath / -OpenClawInstallDir. Don't have one? Run
    install-nodejs-openclaw.ps1 first (see below) -- it fetches both and
    prints the exact paths to pass here.
  - Windows has curl.exe / robocopy.exe built in (they do on Win10+).
  - Outbound internet to nodejs.org and registry.npmjs.org, ONLY if you use
    install-nodejs-openclaw.ps1 to fetch Node.js/OpenClaw. Not needed if you
    already have both.

DON'T HAVE NODE.JS / OPENCLAW YET?
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install-nodejs-openclaw.ps1
  Downloads a pinned, SHA256-verified Node.js build and installs the
  "openclaw" package from the public npm registry, laid out exactly how this
  test expects them. Prints the -NodeExePath / -OpenClawInstallDir values to
  pass through. One-time step (or pass -Force to re-fetch); if you already
  have a working install elsewhere, skip this and point directly at it.

HOW TO RUN
  1. Open PowerShell in THIS folder.
  2. Run:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\run-openclaw-forward-test.ps1 `
          -WxcExecPath C:\mxc-kit\bin\wxc-exec.exe `
          -NodeExePath C:\path\to\node.exe `
          -OpenClawInstallDir C:\path\to\node_modules\openclaw

     Add -Backend isolation_session to exercise that backend instead of the
     default process_container.

  The script COPIES your node.exe, the OpenClaw install, and this package's
  own openclaw-capture.mjs / openshell-supervisor-relay.exe into a share_dir
  (default C:\openshell-openclaw) before creating the sandbox -- the
  AppContainer here can only read paths under share_dir, so everything the
  sandboxed process touches has to live there. The OpenClaw copy uses
  robocopy and only re-copies changed files on a rerun.

WHAT YOU GET BACK
  The script prints PASS/FAIL and creates:
        results-openclaw-forward-<timestamp>.zip
  Hand that zip back. It contains the transcript, gateway logs (including the
  sandbox's own forwarded stdout/stderr), the `openshell forward service`
  output, the raw OpenClaw health-check response, OpenClaw's own captured
  log, and the exact config + policy used.

  The capture wrapper also makes one credential-free WebSocket handshake to
  OpenClaw from inside the sandbox after the gateway reports ready. It records
  only an outcome and response-byte count, never response content. This is a
  diagnostic boundary check: a local response with a failed host-side health
  check points at the sandbox-boundary/forward path; no local response points
  at the sandboxed OpenClaw target. A `started-no-completion` outcome means
  even the probe's bounded socket/timer callbacks stopped progressing after
  OpenClaw reported ready, which is evidence of a blocked target event loop.
  The diagnostic never changes the PASS/FAIL verdict, which still requires
  the authenticated host-side OpenClaw client.

FILES IN THIS PACKAGE
  openshell-gateway.exe          the gateway (self-contained; needs only VC++ runtime)
  openshell.exe                  the CLI
  openshell-supervisor-relay.exe generic spawn+relay-bridge binary the driver
                                  launches inside the sandbox in place of
                                  OpenClaw directly (OpenClaw itself has no
                                  relay awareness)
  openshell-mxc-peer.exe         optional separate AppContainer helper used as
                                  MXC's per-sandbox allowedProxyPeer for
                                  governed egress; not used by this forwarding
                                  test because peer mode rejects forwarding
  openclaw-capture.mjs           thin Node.js wrapper that appends the
                                  sandboxed process's stdout/stderr to a log
                                  file in share_dir and records only the
                                  outcome/byte count of a credential-free
                                  target-side self-probe (OpenShell's own
                                  adapter code, not OpenClaw's)
  mxc-openclaw-gateway.toml      gateway/driver config (process_container, default)
  mxc-openclaw-isolation.toml    gateway/driver config (-Backend isolation_session)
  mxc-openclaw-localnet.toml     experimental alternate process_container config
                                  (-UseLocalNetwork; currently non-functional,
                                  see run-openclaw-forward-test.ps1's own comment)
  openclaw-gateway.yaml          sandbox policy (read-write grant to share_dir
                                  only -- see the comment at its top for why)
  run-openclaw-forward-test.ps1  the orchestrator you run
  run-openclaw-forward-mock.ps1  helper used by -Mock for hosted CI wiring
  install-nodejs-openclaw.ps1    optional prerequisite: fetches Node.js +
                                  OpenClaw if you don't already have them
  README-openclaw-forward.txt    this file

NOTES
  - -Mock runs the gateway, CLI, policy, and an in-policy proof command with
    the in-process wxc shim. It needs no Node.js or OpenClaw install and does
    not test the relay, WebSocket forwarding, OpenClaw, proxy behavior, or MXC.
  - The control plane between CLI and gateway runs with --disable-tls on
    loopback (that's a separate test point, T2). The forwarded application
    traffic uses the driver's separate authenticated relay.
  - A "supervisor session not connected" / ssh 255 message during sandbox
    create is EXPECTED on MXC and harmless - the agent already ran in-driver.
  - `pc_minimal_env = true` in mxc-openclaw-gateway.toml (process_container
    only) means the sandboxed process gets ONLY the env vars passed by
    run-openclaw-forward-test.ps1 to `sandbox create`. That includes the
    non-obvious minimum Windows values needed for CreateProcessW, independent
    of anything Node.js-specific. isolation_session does not need this mode.
  - The relay is entirely on-demand: nothing is listening on any fixed host
    port before you run `openshell forward service`, and nothing is left
    listening after the forward process exits.
  - MXC 1.0 dynamic forwarding requires the default mode's broad private-network
    ingress and host-loopback posture. PASS does not claim sandbox-local-only
    networking or private-network ingress isolation.
  - Proxy-peer mode denies the target workload direct Internet and arbitrary
    host-loopback access, but MXC 1.0 supplies no identity-scoped reverse path
    for dynamic forwarding. This example leaves `pc_proxy_peer_path` empty.
