# Docker-backed gateways

The sandbox container's log holds the sandbox runtime's warnings and the
main process's stdout and stderr when it runs without a TTY. The supervisor
container's log holds supervisor diagnostics and OCSF shorthand. With
`ocsf_json_enabled=true`, it also contains compact `OCSF-JSON` records for
log collectors. Read these through `docker logs <supervisor-container>`;
`docker cp` does not expose the live `/var/log` tmpfs, and workload exec
accesses a separate filesystem. See the published
[OCSF JSON export guide](https://docs.nvidia.com/openshell/latest/observability/ocsf-json-export)
for the marker format and delivery limits.

```bash
docker info
docker ps --filter name=openshell
docker logs <container> --tail=200
docker run --rm --entrypoint /openshell-sandbox "${OPENSHELL_SANDBOX_RUNTIME_IMAGE:-ghcr.io/nvidia/openshell/sandbox:latest}" --version
openshell status
```

For Docker GPU failures, check CDI support and NVIDIA CDI discovery separately:

```bash
docker info --format '{{json .CDISpecDirs}}'
docker info --format '{{json .DiscoveredDevices}}'
for dir in /etc/cdi /var/run/cdi; do
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.json' \) -print
  else
    echo "$dir missing"
  fi
done
systemctl is-enabled nvidia-cdi-refresh.service nvidia-cdi-refresh.path || true
systemctl is-active nvidia-cdi-refresh.service nvidia-cdi-refresh.path || true
systemctl status nvidia-cdi-refresh.service nvidia-cdi-refresh.path --no-pager --lines=50
journalctl -u nvidia-cdi-refresh.service --no-pager --lines=100
```

When the NVIDIA Container Toolkit CDI refresh units are not enabled or no NVIDIA CDI spec has been generated, enable them and trigger a refresh:

```bash
sudo systemctl enable --now nvidia-cdi-refresh.path
sudo systemctl enable --now nvidia-cdi-refresh.service
sudo systemctl restart nvidia-cdi-refresh.service
docker info --format '{{json .DiscoveredDevices}}'
```

Common findings:

- Docker daemon unavailable: start Docker Desktop or Docker Engine.
- Gateway process stopped: inspect exit status and logs.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Numeric workload identities `1` through `4294967294` are accepted; root, the invalid identity sentinel, and missing identities are rejected.
- Sandbox fails before readiness with an OCI workspace validation error: inspect the image's `WorkingDir` using the immutable image ID reported by the gateway. Empty, `/`, and explicit `/sandbox` use the managed `/sandbox` compatibility workspace. Any other workdir must be an absolute normalized directory with no symlink components; the final policy UID, primary GID, and supplementary groups must pass the kernel's effective traverse/write checks, including POSIX ACL and LSM decisions. OpenShell does not create, chown, or chmod a non-default image workdir.
- Docker and Podman also reject an image `VOLUME` or driver mount that covers the workdir or one of its parents because the runtime would mask the immutable path before validation. Move the `VOLUME` below the workspace or remove the declaration.
- Custom Docker and Podman workspace changes live in the workload container's writable layer, not a managed named volume. Stop/start of the same container retains them; removing or replacing that container does not. Export files you need before deleting the sandbox.
- A workdir rejected as a special filesystem or OpenShell control-path collision cannot be made valid with permissions. Move the image workdir away from kernel-backed mounts and the concrete supervisor, TLS, token, runtime, and socket paths named in the error.
- Local Docker gateway setup cannot copy `openshell-sandbox` after exporting a supervisor image: the sandbox runtime and supervisor are separate artifacts. The runtime image must provide `/openshell-sandbox`; the supervisor image provides `/openshell-supervisor`.
- Docker driver cannot initialize because it cannot find `openshell-sandbox`: verify the sibling binary next to `openshell-gateway`, or that the configured `sandbox_runtime_image` contains `/openshell-sandbox`.
- Sandbox never registers: check gateway logs and the supervisor's gateway endpoint.
- SSH host-key startup errors: use matching gateway, compute-driver, and supervisor releases. The gateway retains each sandbox's SSH key in its configured credential store and sends it only through the supervisor bootstrap bundle. Check credential-driver availability and compare the public `host_key_fingerprint` from sandbox JSON output; never print the bootstrap bundle or private key. A missing stored key for a sandbox with a fingerprint is an error, not permission to replace its identity. See the [sandbox SSH identity documentation](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview).
- Calls to an external tool server fail while the sandbox is Ready: inspect `Tool server connections` in `openshell sandbox get <name>`. For configured MCP-over-HTTP endpoints, JSON output exposes each address together with `last_result` and `last_reported_at` in `endpoint_statuses`. Select the endpoint by host, path, and ports, then check the reported failure boundary. `last_reported_at` records gateway acceptance time and can advance when retained evidence is accepted after a reset. Results do not expire or prove current availability; `HttpResponseReceived` can still contain a tool error. If several paths share a host and port, a failure before the path is known remains in logs. Verify the actual operation when current tool availability matters.
- On Docker Desktop, repeated `Policy fetch failed after 5 attempts` messages
  can mean host networking is disabled. Enable host networking in Docker
  Desktop, ensure Enhanced Container Isolation is disabled, and verify the
  gateway's primary endpoint is reachable from a host-networked container.
- Sandbox runtime image exits before printing `openshell-sandbox --version`: verify the configured image contains a static executable at `/openshell-sandbox`.
- A sandbox with explicit `protocol: tcp` endpoints fails before workload readiness: confirm the selected isolation backend advertises TCP mediation, then inspect the sandbox and supervisor logs for protected-channel setup or listener failures. A driver that cannot supply the required outer egress fence and authenticated runtime channel must reject the policy before starting the agent.
- Supervisor runtime validation fails: verify `supervisor_image` contains an `/openshell-supervisor` executable from the same release as the sandbox runtime, and that the dynamic loader and shared libraries it links against are available inside that image. `docker run --rm --network none --entrypoint /openshell-supervisor <supervisor_image> --version` should print that release; a `no such file or directory` error for a binary that exists means the loader or a library is missing. The supervisor runs from its own image and does not need to be static; only `/openshell-sandbox` must be.
- The sandbox fails its enforcement probe: inspect the sandbox log for the exact nested seccomp user-notification, task-memory, Landlock, loopback DNS, or socket-injection check that failed. A runtime may return `ENOSYS` for `process_vm_readv` and `process_vm_writev` while satisfying the production parent-to-workload-child task-memory probe through `/proc/<pid>/mem`; only failure of both backends is fatal. Do not add capabilities or switch to an unconfined seccomp profile; use a runtime whose default profile permits the unprivileged probe.
- A GPU sandbox fails because Docker reports no discovered NVIDIA CDI devices: verify `.DiscoveredDevices` contains entries such as `nvidia.com/gpu=all`, verify `/etc/cdi` or `/var/run/cdi` contains a generated NVIDIA spec, and check that `nvidia-cdi-refresh.service` and `nvidia-cdi-refresh.path` from NVIDIA Container Toolkit are enabled and healthy. The service is a one-shot unit, so `inactive (dead)` can be normal after a successful run; use `systemctl status` and `journalctl` to distinguish success from a skipped or failed refresh. Restart `nvidia-cdi-refresh.service` to regenerate missing or stale CDI specs, then restart or reload Docker and re-check `docker info`.
- Docker or Podman rejects an explicit `cdi_devices` selector: use a CDI qualified name (`<vendor>/<class>=<name>`), not a host-device path. Syntax validation accepts other vendors; it does not establish that the runtime has the device or that its GPU workload is supported. Consult the published GPU selection documentation for request requirements.

## Corporate upstream proxy

Docker corporate proxy settings are operator-owned fields under
`[openshell.drivers.docker]`. Confirm the complete proxy table and inspect the
companion supervisor command and logs:

```bash
grep -A20 '^\[openshell.drivers.docker\]' <gateway.toml> | grep -E 'https_proxy|no_proxy|proxy_auth_file|proxy_auth_allow_insecure|proxy_connect_by_hostname|proxy_ca_bundle'
docker ps --filter label=openshell.ai/isolation-role=supervisor
docker inspect --format '{{json .Config.Cmd}} {{json .Mounts}}' <supervisor-container>
docker logs <supervisor-container> --tail=200 | grep -Ei 'upstream|connect|proxy|certificate'
```

`proxy_ca_bundle` names a gateway-host PEM file and requires `https_proxy`.
The proxy URL may use `http://` or `https://`; a plain HTTP proxy may still
re-sign destination TLS. Missing, unreadable, empty, oversized, malformed, or
certificate-free bundles fail closed. The Docker driver copies a validated
bundle into its supervisor-only named volume and passes the fixed path
`/.openshell/supervisor/upstream-proxy-ca-bundle.pem`. The gateway-host path
must not appear in container arguments, mounts, workload environment, or
`template.driver_config.docker`.

An HTTPS proxy certificate error usually means the bundle lacks the proxy
listener issuer or its certificate does not match the proxy hostname. A
TLS-intercepted destination error means the re-signing issuer is missing or the
supervisor did not receive the bundle. Keep verification enabled and correct
the operator bundle.
