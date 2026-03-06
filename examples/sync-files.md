# Syncing Files To and From a Sandbox

Move code, data, and artifacts between your local machine and a NemoClaw
sandbox using `nemoclaw sandbox upload` and `nemoclaw sandbox download`.

## Push local files into a sandbox

Upload your current project directory into `/sandbox` on the sandbox:

```bash
nemoclaw sandbox upload my-sandbox .
```

Push a specific directory to a custom destination:

```bash
nemoclaw sandbox upload my-sandbox ./src /sandbox/src
```

Push a single file:

```bash
nemoclaw sandbox upload my-sandbox ./config.yaml /sandbox/config.yaml
```

## Pull files from a sandbox

Download sandbox output to your local machine:

```bash
nemoclaw sandbox download my-sandbox /sandbox/output ./output
```

Pull results to the current directory:

```bash
nemoclaw sandbox download my-sandbox /sandbox/results
```

## Sync on create

Push all git-tracked files into a new sandbox automatically:

```bash
nemoclaw sandbox create --sync -- python main.py
```

This collects tracked and untracked (non-ignored) files via
`git ls-files` and streams them into `/sandbox` before the command runs.

## Workflow: iterate on code in a sandbox

```bash
# Create a sandbox and sync your repo
nemoclaw sandbox create --name dev --sync --keep

# Make local changes, then push them
nemoclaw sandbox upload dev ./src /sandbox/src

# Run tests inside the sandbox
nemoclaw sandbox connect dev
# (inside sandbox) pytest

# Pull test artifacts back
nemoclaw sandbox download dev /sandbox/coverage ./coverage
```

## How it works

File sync uses **tar-over-SSH**. The CLI streams a tar archive through the
existing SSH proxy tunnel -- no `rsync` or other external tools required on
your machine. The sandbox base image provides GNU `tar` for extraction.

- **Push**: `tar::Builder` (Rust) -> stdin | `ssh <proxy> sandbox "tar xf - -C <dest>"`
- **Pull**: `ssh <proxy> sandbox "tar cf - -C <dir> <path>"` | stdout -> `tar::Archive` (Rust)
