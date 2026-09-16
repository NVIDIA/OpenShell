OpenShell MXC - OpenClaw + dynamic forward test (both backends)
=======================================================================

WHAT THIS PROVES
  The full path for reaching a service inside an MXC sandbox that has NO
  in-sandbox supervisor process (ProcessContainer additionally has NO
  inbound network capability at all):
    gateway -> MXC driver -> ProcessContainer OR isolation_session sandbox
      -> openshell-supervisor-relay launches OpenClaw's gateway inside it,
         with no relay awareness in OpenClaw itself
      -> `openshell forward service --target-port 18889` opens a fresh,
         on-demand WebSocket relay for THIS call only (nothing pre-declared
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
  - An ELEVATED (Administrator) PowerShell session, for -Backend
    process_container specifically. On this box's wxc-exec build,
    process_container falls back to an "AppContainer + DACL" isolation
    tier that needs two privileged operations: (1) WRITE_DAC on share_dir
    to stamp the AppContainer's ACL -- fixable non-elevated if you own
    share_dir yourself (first run wins ownership; icacls /setowner fixes a
    folder an earlier elevated run left owned by Administrators), but
    (2) with egress_proxy = true (mxc-openclaw-gateway.toml's default),
    wxc-exec also calls NetworkIsolationSetAppContainerConfig to grant the
    AppContainer a loopback exemption so it can reach the host's egress
    proxy -- that Windows API requires Administrator regardless of file
    ownership. Non-elevated fails both with ERROR_ACCESS_DENIED (0x5), the
    second as "Network proxy error: Failed to set loopback exemption:
    0x00000005". -Backend isolation_session does not hit either path.
  - wxc-exec.exe present (default expected: C:\mxc-kit\bin\wxc-exec.exe)
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
  install-nodejs-openclaw.ps1    optional prerequisite: fetches Node.js +
                                  OpenClaw if you don't already have them
  README-openclaw-forward.txt    this file

NOTES
  - The control plane between CLI and gateway runs with --disable-tls on
    loopback (that's a separate test point, T2). This test's relay traffic
    (host <-> sandbox) is a separate, unrelated WebSocket tunnel.
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
