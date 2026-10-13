# Syncing Files To and From a Sandbox

Move code, data, and artifacts between your local machine and an OpenShell
sandbox using `openshell sandbox upload` and `openshell sandbox download`.

## Push local files into a sandbox

Upload your current project directory into `/sandbox` on the sandbox:

```bash
openshell sandbox upload my-sandbox .
```

Push a specific directory to a custom destination:

```bash
openshell sandbox upload my-sandbox ./src /sandbox/src
```

Push a single file:

```bash
openshell sandbox upload my-sandbox ./config.yaml /sandbox/config.yaml
```

## Pull files from a sandbox

Download sandbox output to your local machine:

```bash
openshell sandbox download my-sandbox /sandbox/output ./output
```

Pull results to the current directory:

```bash
openshell sandbox download my-sandbox /sandbox/results
```

## Sync on create

Push all files in the current directory into a new sandbox automatically:

```bash
openshell sandbox create --upload . -- python main.py
```

This uploads the current directory into `/sandbox` before the command runs.

## Workflow: iterate on code in a sandbox

```bash
# Create a sandbox and upload your repo
openshell sandbox create --name dev --upload .

# Make local changes, then push them
openshell sandbox upload dev ./src /sandbox/src

# Run tests inside the sandbox
openshell sandbox connect dev
# (inside sandbox) pytest

# Pull test artifacts back
openshell sandbox download dev /sandbox/coverage ./coverage
```

## How it works

File sync uses the native OpenShell streaming file-transfer protocol. The CLI
creates and extracts tar streams in Rust, and the sandbox performs the matching
operation under the workload identity. Transfers use bounded frames with
backpressure, cancellation, and explicit completion; they do not require
`ssh`, `scp`, `rsync`, or a `tar` executable in the workload image.
