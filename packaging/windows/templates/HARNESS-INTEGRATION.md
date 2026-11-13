# Harness integration

Use the OpenShell CLI or matching gateway SDK. The gateway embeds the MXC driver and launches the host supervisor and Windows boundary executable; callers do not implement the internal Sandbox Protocol.

Initialize the gateway using the supplied script. Per-workload command arrays and absolute working directories belong in template.driver_config.mxc (rawSpec.template.driverConfig.mxc in TypeScript). The local gateway template explicitly enables allow_driver_config. Supply workload environment through the normal CLI or SDK fields and grant only required filesystem and network access in policy.

The examples create detached, one-shot commands and read their workspace output. They do not qualify interactive attachment or arbitrary workload executables. Delete workloads before stopping the gateway. When deletion returns an accepted result, wait for completion.

Use the SDK artifacts from this kit because the main-branch SDK may have a different wire contract. The Python example checks health only. Consult VALIDATION.md for tested operations.
