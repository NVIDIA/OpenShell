OpenShell MXC - ETW -> OCSF audit-trail example
===============================================

WHAT THIS PROVES / PRODUCES
  The full Windows OCSF audit path on this box:
    gateway -> MXC driver -> process_container sandbox
      -> the OS "Sandboxing" ETW provider fires as the sandbox is created
      -> the gateway's in-process consumer decodes each event, attributes it to
         an OpenShell sandbox_id, and maps it to OCSF
      -> events are written to a durable JSONL audit log AND printed as
         human-readable shorthand.

  The deliverable is the OCSF log: openshell-ocsf.<date>.log, one OCSF event
  object per line - the same schema and medium the Linux OpenShell pipeline
  produces (Windows is at functional parity).

  OCSF classes you will see:
    [6002] Application Lifecycle        - sandbox created
    [5019] Device Config State Change   - OS policy / hardening / proxy / console
    [1007] Process Activity             - in-sandbox process launch (+ cmd line)
    [2004] Detection Finding            - MXC setup activity errors (informational)

PREREQUISITES (on this test box)
  - wxc-exec.exe present (default expected: C:\mxc-kit\bin\wxc-exec.exe)
  - process_container backend live (it was for our earlier runs)
  - Run ELEVATED (Run as administrator) OR from an account in the
    'Performance Log Users' group. Opening the real-time ETW session needs this;
    without it the run fails fast with a clear message.

HOW TO RUN
  1. Open an ELEVATED PowerShell in THIS folder.
  2. Run:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\run-ocsf-audit.ps1
     If wxc-exec is somewhere else:
        ... -File .\run-ocsf-audit.ps1 -WxcExecPath "D:\path\to\wxc-exec.exe"

WHAT YOU GET BACK
  The script prints PASS/FAIL + an event-type coverage count and class breakdown,
  points you at the OCSF audit log, and creates:
        results-<timestamp>.zip
  It contains the OCSF audit log (openshell-ocsf.<date>.log), the full transcript,
  the gateway logs (with the human-readable OCSF shorthand), a summary, and the
  exact config + policy used. To auto-copy the bundle to a shared location, pass
  -ShareOut '\\server\share' (off by default; results stay local otherwise).

FILES IN THIS PACKAGE
  openshell-gateway.exe    the gateway (self-contained; needs only VC++ runtime)
  openshell.exe            the CLI
  mxc-ocsf-audit.toml      gateway/driver config (process_container, etw_audit=true, egress proxy)
  ocsf-audit.yaml          sandbox policy (read-write grant to the share dir)
  run-ocsf-audit.ps1       the orchestrator you run
  README-ocsf-audit.txt    this file
  (wxc-exec.exe is used IN PLACE on the box; not shipped)

USEFUL OPTIONS
  -SandboxCount <n>   Create n sandboxes (default 2). More sandboxes = more events.
  -NoProxy            Skip the per-sandbox egress proxy. This omits ONLY the
                      SandboxProxyConfigured config event; everything else is
                      still produced. (Default is proxy ON for the full set.)
  -WxcExecPath <path> Path to wxc-exec.exe on this box.
  -ShareOut <path>    Copy the results bundle to a shared location
                      (e.g. \\server\share). Off by default (results stay local).
  -KeepRunning        Leave the gateway running afterward for inspection.

NOTES
  - The control plane between CLI and gateway runs with --disable-tls on loopback;
    that is unrelated to the OCSF audit path this example exercises.
  - A "supervisor session not connected" / ssh 255 message during sandbox create
    is EXPECTED on MXC and harmless - the agent already ran in-driver.
  - The proxy path requires the host-side CONNECT proxy and an absolute agent
    binary (the packaged config uses C:\Windows\System32\cmd.exe); the run script
    handles this for you.
  - The Sandboxing provider reports the sandbox entry-point process, not the full
    in-sandbox process tree. Deep process-tree auditing would need a second ETW
    source (Microsoft-Windows-Kernel-Process) and is out of scope for this trail.
  - cmd_line is captured verbatim into OCSF process.cmd_line with no redaction on
    this path; treat the audit log as sensitive at rest and in transit.
