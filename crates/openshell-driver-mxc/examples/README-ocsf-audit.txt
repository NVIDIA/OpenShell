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
    [1007] Process Activity             - in-sandbox process launch (+ executable identity)
    [2004] Detection Finding            - MXC setup activity errors (informational)

PREREQUISITES (on this test box)
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
  -ShareDir <path>    Host folder granted read-write to the workload. The script
                      derives a disposable policy and per-sandbox config for it.
  -WxcExecPath <path> Path to wxc-exec.exe on this box.
  -ShareOut <path>    Copy the results bundle to a shared location
                      (e.g. \\server\share). Off by default (results stay local).
  -KeepRunning        Leave the gateway running afterward for inspection.
  -SandboxingProviderGuid <guid>
                      Override the OS ETW provider GUID the consumer listens
                      on. Use this if a run reports "event coverage: 0 of 8"
                      with "sandbox_ids distinct in log: 0" despite the
                      sandboxes completing successfully -- the gateway log
                      line "MXC ETW->OCSF consumer has received zero events
                      from the Sandboxing provider despite sandbox activity"
                      confirms this. The built-in default
                      (f6ec123e-314e-400b-9e0a-151365e23083) is this
                      consumer's best-known identity for the OS "Sandboxing"
                      TraceLogging provider, but that provider is not
                      manifest-registered, so its GUID is not independently
                      verifiable, and it has been observed entirely absent
                      from `logman query providers` / `Get-WinEvent
                      -ListProvider` enumeration on at least one Windows
                      Insider/ARM64 build (see nvbugs 6782870). This option
                      does not discover the correct GUID for you -- it is an
                      escape hatch for an operator who has independently
                      confirmed it, e.g. from a known-good MXC/wxc-exec
                      build's own ETW manifest. Accepts a bare
                      (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) or braced
                      ({...}) GUID. Leave unset to keep the built-in default.

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
  - MXC process audit events record the executable basename only. Command-line
    arguments are omitted from OCSF JSON and shorthand because they can contain
    credentials, signed URLs, or PII.
