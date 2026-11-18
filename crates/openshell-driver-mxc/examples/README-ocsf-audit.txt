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
  produces.

  OCSF classes you will see:
    [6002] Application Lifecycle        - sandbox created
    [5019] Device Config State Change   - OS policy / hardening / proxy / console
    [1007] Process Activity             - in-sandbox process launch (+ executable identity)
    [2004] Detection Finding            - MXC setup activity errors (informational)

PREREQUISITES (on this test box)
  - wxc-exec.exe present (default expected: C:\mxc-kit\bin\wxc-exec.exe)
  - process_container backend live
  - OpenSSL on PATH to generate disposable supervisor signing keys
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
  openshell-supervisor.exe host supervisor
  openshell-windows-sandbox.exe sandbox runtime
  libz3.dll                matching native Z3 runtime
  mxc-ocsf-audit.toml      gateway/driver config (process_container, etw_audit=true, egress proxy)
  ocsf-audit.yaml          sandbox policy (read-write grant to the share dir)
  run-ocsf-audit.ps1       the orchestrator you run
  README-ocsf-audit.txt    this file
  (wxc-exec.exe is used IN PLACE on the box; not shipped)

USEFUL OPTIONS
  -SandboxCount <n>   Create n sandboxes (default 2). More sandboxes = more events.
  -ShareDir <path>    Host folder granted read-write to the workload. The script
                      derives a disposable policy and per-sandbox config for it.
  -WxcExecPath <path> Path to wxc-exec.exe on this box.
  -ShareOut <path>    Copy the results bundle to a shared location
                      (e.g. \\server\share). Off by default (results stay local).
  -KeepRunning        Leave the gateway running afterward for inspection.

NOTES
  - Disposable supervisor signing keys are protected outside the results bundle
    and removed after the gateway stops (retained with -KeepRunning).
  - The control plane between CLI and gateway runs with --disable-tls on loopback;
    that is unrelated to the OCSF audit path this example exercises.
  - The proxy path requires the host-side CONNECT proxy and an absolute agent
    binary (the packaged config uses C:\Windows\System32\cmd.exe); the run script
    handles this for you.
  - The Sandboxing provider reports the sandbox entry-point process, not the full
    in-sandbox process tree. Deep process-tree auditing would need a second ETW
    source (Microsoft-Windows-Kernel-Process) and is out of scope for this trail.
  - MXC process audit events record the executable basename only. Command-line
    arguments are omitted from OCSF JSON and shorthand because they can contain
    credentials, signed URLs, or PII.

COVERAGE
  All seven required ETW event types must be present in structured JSONL.
  Console shorthand formatting does not affect coverage. The supervisor proxy
  is always provisioned; an OS proxy-configuration event is not required.

CURRENT QUALIFICATION LIMITATION
  On the ARM64 Windows build 28120 / MXC 1.0.0 test host, the Sandboxing provider
  emits from the shared Appinfo broker. The consumer's executor PID/generation
  anchor cannot correlate those records, so this qualification remains FAIL.
  Captured records are not sufficient: all seven attributed JSONL event types
  are still required. Do not use the shared broker PID as a sandbox identity.
