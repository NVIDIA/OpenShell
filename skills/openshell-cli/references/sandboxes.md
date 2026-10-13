# Sandboxes

Create, run, connect to, and clean up sandboxes. `openshell agent context` lists the exact flags.

## Create your first sandbox

The simplest way to get a sandbox running:

```bash
openshell sandbox create
```

This creates a sandbox whose canonical main process is `/bin/bash -l` and
attaches your terminal to that retained process. Add `--detach` to return after
the sandbox becomes ready without attaching.

An explicit trailing command is foreground even when stdin or stdout is not a
terminal. The CLI streams its stdout and stderr and reports the command's exit
status after output drains. A failure to deliver output makes the CLI report a
failure even if the command itself exited successfully; check the sandbox's
state before retrying work that might have side effects. Exit code 0 leaves a
retained sandbox in `Completed`; nonzero leaves it in `Error` with
`MainProcessFailed`. Use `--no-keep` to delete either result after output
drains, or `--detach` for a long-running service. Combine
`--detach --no-keep` when the gateway should run the service without a host
attachment and delete its sandbox after the service exits.

When supplying `--name`, use a portable DNS-1123 label: at most 63 lowercase alphanumeric or `-` characters, beginning and ending with an alphanumeric character. The Kubernetes driver rejects uppercase letters, underscores, dots, and other names that cannot become Kubernetes resource labels.

Provider attachment is explicit. Name each provider with `--provider`; the
trailing command does not select or attach one. If the named provider does not
exist but a profile with that ID is available, the CLI can create it from local
credentials:

```bash
openshell sandbox create --from registry.example.com/your-org/claude-agent:latest --provider claude-code -- claude
openshell sandbox create --from registry.example.com/your-org/codex-agent:latest --provider codex -- codex
```

The agent will be prompted interactively if credentials are missing.

### Exit and clean up

Exit the sandbox shell with `exit`, or detach with Ctrl-D, then:

```bash
openshell sandbox delete <name>
```

## Create with options

```bash
openshell sandbox create \
  --name my-sandbox \
  --provider my-github \
  --provider my-claude \
  --policy ./my-policy.yaml \
  --upload .:/workspace \
  --label team=agents \
  --detach
openshell sandbox exec my-sandbox --tty -- claude
```

`openshell agent context` lists every create flag with its values and conflicts. Behavior it does not show:

- `--cpu`, `--memory`: Docker and Podman apply limits; Kubernetes applies matching requests and limits.
- `--driver-config-json`: experimental driver-specific configuration, disabled unless the administrator allows it (see templates below).
- `--template NAME`: takes image, environment, sizing, and driver configuration from a template, so it conflicts with the inline workload flags.
- `--tty`: allocates a retained PTY for the canonical main process.
- `--restart-policy`: gateway-owned restart of the main process; `never` is the default.
- `--upload`: uploads into the container working directory unless a destination follows the colon.
- `--no-keep`: deletes the sandbox after main output and the exit result drain.
- `--forward`, `--editor`, `--expose`: keep the sandbox alive.

`--detach` adds no attachment grace period. When the canonical process exits,
its terminal phase is reported immediately. A foreground create declares one
expected main-process SSH attachment; cleanup finalizes after that connection
closes naturally. With `--detach --no-keep`, the gateway owns the detached
process lifecycle and deletes the ephemeral sandbox after terminal reporting
finishes.

Do not combine `--upload` with a trailing main command. Uploads currently finish
after the canonical process starts; create a scratch sandbox and use
`sandbox exec`, or build the files into the image.

Create from a reusable workload template when several sandboxes should share
image, environment, sizing, or driver-specific configuration:

```bash
openshell sandbox template create gpu-kata \
  --image registry.example.com/agents/python:latest \
  --cpu 2 \
  --memory 4Gi \
  --gpu 1 \
  --driver-config-json '{"kubernetes":{"pod":{"node_selector":{"pool":"gpu"}}}}'

openshell sandbox create --name my-sandbox --template gpu-kata --provider my-github -- claude
```

Driver config is disabled by default. These template and one-off
`sandbox create --driver-config-json` examples require the administrator to set
`allow_driver_config = true` for the selected driver. This does not waive
resource admission: external attachments need administrator-controlled approval
labels on the actual resources, not sandbox labels. GPU device attachments
are temporarily exempt from labels; the public `--gpu` flag needs no driver
config opt-in. Consult the published gateway configuration reference before
changing admission settings; do not recommend disabling admission to bypass a
denial. Put driver config on a template only when it should be reused.

## Manage sandbox workload templates

```bash
openshell sandbox template create gpu-kata \
  --image registry.example.com/agents/python:latest \
  --cpu 2 \
  --memory 4Gi \
  --gpu 1 \
  --label team=runtime \
  --env FEATURE_FLAG=on
openshell sandbox template list
openshell sandbox template list --label-selector team=runtime
openshell sandbox template list --all-workspaces --output json
openshell sandbox template get gpu-kata
openshell sandbox template delete gpu-kata
```

Template `--image` accepts an OCI image reference. If omitted, the gateway
applies its default sandbox image when creating a sandbox from the template.
Create-time policy, providers, labels, uploads, forwarding, editor launch, and
the initial command stay on `sandbox create`.

## List and inspect sandboxes

```bash
openshell sandbox list
openshell sandbox list --selector team=agents --output json
openshell sandbox get my-sandbox
```

Most commands with an optional sandbox name use the last-used sandbox. Pass an explicit name in automation.

## Connect to a running sandbox

```bash
openshell sandbox connect my-sandbox
openshell sandbox connect my-sandbox --editor vscode
```

Attaches to the sandbox's existing canonical main process. Disconnecting leaves
that process running; reconnecting targets the same process instance and replays
recent output. If an established SSH transport is interrupted, such as when a
laptop sleeps and wakes, the CLI retries transient failures for up to 60 seconds
and reattaches to that same process. Use `sandbox exec --tty -- /bin/bash -l`
for a new shell. Press `Ctrl-D` or `Ctrl-P`, then `Ctrl-Q` to disconnect without
terminating main. OpenSSH's `~.` escape looks like transport loss and therefore
starts automatic recovery; after it reattaches, use `Ctrl-D` or `Ctrl-P`, then
`Ctrl-Q` to exit, or press `Ctrl-C` between retry attempts to cancel recovery.
When you own stdin, `Ctrl-C` interrupts the foreground process. In a read-only
attachment, `Ctrl-C` or `Ctrl-D` exits the viewer and leaves main and other
attachments running. Configure VS Code Remote-SSH with:

```bash
openshell sandbox ssh-config my-sandbox >> ~/.ssh/config
```

A writable attachment that finds another attachment holding stdin reports `attached read-only; retry input after the owner disconnects`. Automatic recovery can hit this when it reattaches before the supervisor closes the dead connection. The supervisor closes a connection 60 seconds after it last received bytes from it, which can be later than 60 seconds after the network failed if the relay buffered data. After the old owner disconnects or times out, send the input you meant to type next. If stdin is free, the attachment prints `input enabled` and forwards that input to the process, so do not probe with Enter or a prompt answer such as `y`. If nothing prints, the old connection still holds stdin. Input sent while the attachment was read-only never reaches the process, so send it again later. `Ctrl-C`, `Ctrl-D`, and `Ctrl-P` then `Ctrl-Q` still exit a read-only attachment instead of enabling input; enable input first if you need `Ctrl-C` to interrupt the process. Recovery never takes stdin from a healthy owner, and an explicitly read-only attachment stays read-only.

If `connect` reports `canonical main process already finished`, inspect the
result with `sandbox get`. A pending foreground attachment can still retrieve
retained output in `Completed` or `Error`; phase alone does not determine
whether attachment is available. A nonzero main-process exit under
`on-failure`, or any exit under `always`,
moves the sandbox to `Starting` during backoff and resource replacement. Connect
and exec commands resume after the new supervisor session makes it `Ready`.
An explicit `sandbox stop` cancels a pending restart.

## Upload and download files

```bash
# Upload local files to the sandbox working directory
openshell sandbox upload my-sandbox ./src

# Download a path relative to the sandbox working directory
openshell sandbox download my-sandbox output ./local-output
```

Uploads use bounded streaming and wait for sandbox input consumption; the 4 MiB process-input budget is not a total upload-size limit. Upgrade both the CLI and the supervisor runtime used by the sandbox. An older supervisor rejects the upload protocol before file data is sent. Failed or canceled uploads may leave incomplete files in the destination; check it before retrying or remove the partial files.

Uploads inside a Git work tree honor `.gitignore` by default and stop if Git filtering fails or selects no files. Sources confirmed to be outside a Git work tree upload without filtering, with a warning that `.gitignore` rules are not applied. Git must be available to determine whether filtering applies; broken or inaccessible repositories stop the upload. Add `--no-git-ignore` for an intentional unfiltered upload. This also applies to `sandbox create --upload`.

`sandbox create --upload` checks every upload locally before provisioning and creates no sandbox if one is rejected. If a transfer fails after provisioning, the sandbox remains running and earlier uploads may have completed. Retry with `sandbox upload` against that sandbox, or remove it with `sandbox delete`.

Uploads preserve symlinks, including dangling symlinks, instead of dereferencing their targets. A symlink source bypasses Git-aware filtering so the link itself is archived.

When the upload destination is omitted, the CLI discovers the remote working
directory. Uploading a named directory merges it into an existing directory of
the same name, overwriting matching entries without deleting unrelated entries.
Downloads accept paths relative to that working directory or absolute paths
within it.

## Execute a non-interactive command

```bash
openshell sandbox exec my-sandbox --workdir /workspace -- ls -la
openshell sandbox exec --name my-sandbox --env MODE=test -- cargo test
```

The sandbox is a positional name or `--name`, not both; omit it to use the
last-used sandbox. `--` is required and everything after it is the remote
command, so put options such as `--tty` before it.

`sandbox exec` starts an independent sibling process and streams output. After
stdout and stderr drain, it returns the remote command's exit code if delivery
succeeds. Output delivery failure instead returns exit code 74, even when the
command exited successfully. A descendant that keeps an inherited output pipe
open for more than 30 seconds after the command exits triggers that failure.
Check whether the command ran before retrying work with side effects. Use
`sandbox connect` to attach to the canonical main process.
Use `--env` only for non-secret values. Attach credentials to the sandbox with a
provider instead of passing API keys, tokens, or other secrets to `sandbox exec`.

## Change attached providers

```bash
openshell sandbox provider list my-sandbox
openshell sandbox provider list my-sandbox --output json
openshell sandbox provider attach my-sandbox my-github --wait --timeout 30
openshell sandbox provider status my-sandbox my-github --output json
openshell sandbox provider detach my-sandbox my-github --wait --timeout 30
```

Structured attachment output contains provider names, types, and sorted
credential and config key names. It never contains credential, handle, or
config values.

## View logs

```bash
# Recent logs
openshell logs my-sandbox

# Stream live logs
openshell logs my-sandbox --tail

# Filter by source and level
openshell logs my-sandbox --tail --source sandbox --level warn

# Logs from the last 5 minutes
openshell logs my-sandbox --since 5m
```

## Delete sandboxes

```bash
openshell sandbox delete my-sandbox
openshell sandbox delete sandbox-1 sandbox-2 sandbox-3   # Multiple at once
openshell sandbox delete --all
```

`deletion accepted` means cleanup is still pending. Inspect the sandbox until
it disappears before assuming completion. An already-absent sandbox succeeds;
missing workspaces and authorization failures remain errors. Do not blindly
retry by name if another process might have recreated that name.

## Stop and start sandboxes

Use stop to halt compute while retaining the sandbox and its persistent
workspace:

```bash
openshell sandbox stop [name]
openshell sandbox start [name]
```

Both commands default to the last-used sandbox. Stop stops background
forwards and waits for `Stopped`; start waits for `Ready`. Connect, exec,
file transfer, forwarding, and exposed services are unavailable while
stopped or completed. Starting a retained `Completed` or
`Error/MainProcessFailed` sandbox launches a fresh canonical-main instance and
invalidates SSH sessions from the previous runtime generation. Delete remains
the operation that removes retained state.

The sandbox's SSH host identity survives stop/start and runtime restarts.
API clients can read its public fingerprint from the sandbox resource or
SSH-session response and pin it to the sandbox ID. Recreating a deleted
sandbox, even under the same name, creates a different identity. See the
[sandbox SSH documentation](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md)
for verification behavior and release compatibility.
