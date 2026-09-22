OpenShell MXC Windows inference demos
====================================

These two demos exercise the full gateway -> MXC processContainer path:

  Local inference (Hello World)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\run-ollama-test.ps1

  Cloud inference (T1)
    $env:NV_API_KEY = "nvapi-..."
    powershell -NoProfile -ExecutionPolicy Bypass -File .\run-inference-test.ps1

Prerequisites
-------------

  - Windows 11 build 26300.8553 or newer with MXC processContainer support.
  - openshell-gateway.exe and openshell.exe beside these files, or explicit
    -GatewayPath and -CliPath arguments.
  - wxc-exec.exe beside these files, on PATH, named by
    OPENSHELL_WXC_EXEC_PATH, or passed with -WxcExecPath.
  - Local demo: an Ollama-compatible service on 127.0.0.1:11434 by default.
    Override -OllamaHost, -OllamaPort, and -Model when needed.
  - Cloud demo: NV_API_KEY and outbound HTTPS to integrate.api.nvidia.com.

The runners use a unique temporary share directory and an available loopback
gateway port for each run. They never require C:\mxc-kit, C:\work, a fixed
gateway port, or edits to the checked-in templates. Missing prerequisites fail
before sandbox creation with a diagnostic naming the parameter or environment
variable that can supply them.

Security model
--------------

Both demos use the fail-closed process_container backend. Their rendered policy
grants only the per-run share and the one requested endpoint, and no broad
AppContainer network capability is enabled. Cloud traffic traverses OpenShell's
enforcing CONNECT proxy. For local Ollama only, curl bypasses proxy variables
for the requested loopback hostname because the proxy's SSRF defense rejects
all loopback destinations; MXC still limits direct traffic to host loopback. This
inherits the driver's documented limitation that governed MXC sandboxes can
reach other host-loopback ports and must not be treated as loopback-service
isolation. The cloud key is passed with `--env-from NV_API_KEY`, is not placed in
argv or written to the results directory, and is never printed.

Each run leaves a results-* directory containing the rendered TOML and policy,
gateway logs, response artifacts, and summary.txt. The script exits 0 only when
the sandbox creates successfully and the expected inference response is
observed. Use -KeepArtifacts to retain the temporary share for debugging.
