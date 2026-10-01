OpenShell CLI <-> gateway mTLS test (T2)
=========================================

WHAT THIS PROVES
  T2 covers the control channel, not inference. It verifies that:

    - the gateway enables TLS, client-certificate verification, and mTLS auth;
    - the CLI can register the gateway and complete a real `sandbox list` RPC;
    - a client that presents no certificate is rejected during the handshake.

  The gateway starts with OpenShell's in-process MXC mock only to satisfy the
  compute-driver startup contract. The test never creates a sandbox and does
  not claim MXC or AppContainer isolation coverage.

PREREQUISITES
  Put this script in a folder containing:

    openshell-gateway.exe
    openshell.exe

  No API key, wxc-exec binary, MXC backend, or network egress is required.
  The gateway uses an in-memory database and the test runs on loopback.

RUN
  powershell -NoProfile -ExecutionPolicy Bypass -File .\run-mtls-test.ps1

  Optional parameters:

    -TlsDir C:\work\openshell-mtls
        Directory for throwaway certificates. Private keys remain here and are
        never copied into the result bundle.

    -Port 17670
        Explicit gateway port. The default, 0, chooses an available loopback
        port. If an explicit port is busy, the test fails without stopping the
        process that owns it.

    -GatewayPath C:\path\to\openshell-gateway.exe
    -CliPath C:\path\to\openshell.exe
        Override the packaged binary paths for local development.

    -OutputDir D:\results\openshell-mtls
        Write the result directory and zip to another location. The default is
        the script folder.

    -KeepRunning
        Leave only the gateway process started by this invocation running.
        The script prints the PID and preserves its isolated CLI state path.

STATE SAFETY
  The script redirects XDG_CONFIG_HOME, XDG_STATE_HOME, and the system gateway
  overlay to a unique test-owned directory beneath TlsDir before generating
  certificates or invoking the CLI. Existing gateway registrations, active
  selection, certificates, and CLI state are never read, overwritten, or
  removed. The original environment is restored before the script exits.

OUTPUT
  results-mtls-<timestamp>-<pid>.zip in OutputDir (the script folder by
  default). The bundle contains gateway logs, transcript.txt, summary.txt, the
  exact non-secret gateway configuration, and the public server certificate.
  It contains no private keys.
