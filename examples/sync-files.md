# Syncing Files To and From a Sandbox

Move code, data, and artifacts between your local machine and a Navigator
sandbox using `navigator sandbox sync`.

## Push local files into a sandbox

Upload your current project directory into `/sandbox` on the sandbox:

```bash
navigator sandbox sync my-sandbox --up .
```

Push a specific directory to a custom destination:

```bash
navigator sandbox sync my-sandbox --up ./src /sandbox/src
```

Push a single file:

```bash
navigator sandbox sync my-sandbox --up ./config.yaml /sandbox/config.yaml
```

## Pull files from a sandbox

Download sandbox output to your local machine:

```bash
navigator sandbox sync my-sandbox --down /sandbox/output ./output
```

Pull results to the current directory:

```bash
navigator sandbox sync my-sandbox --down /sandbox/results
```

## Sync on create

Push all git-tracked files into a new sandbox automatically:

```bash
navigator sandbox create --sync -- python main.py
```

This collects tracked and untracked (non-ignored) files via
`git ls-files` and streams them into `/sandbox` before the command runs.

## Workflow: iterate on code in a sandbox

```bash
# Create a sandbox and sync your repo
navigator sandbox create --name dev --sync --keep

# Make local changes, then push them
navigator sandbox sync dev --up ./src /sandbox/src

# Run tests inside the sandbox
navigator sandbox connect dev
# (inside sandbox) pytest

# Pull test artifacts back
navigator sandbox sync dev --down /sandbox/coverage ./coverage
```

## How it works

File sync uses **tar-over-SSH**. The CLI streams a tar archive through the
existing SSH proxy tunnel -- no `rsync` or other external tools required on
your machine. The sandbox base image provides GNU `tar` for extraction.

- **Push**: `tar::Builder` (Rust) -> stdin | `ssh <proxy> sandbox "tar xf - -C <dest>"`
- **Pull**: `ssh <proxy> sandbox "tar cf - -C <dir> <path>"` | stdout -> `tar::Archive` (Rust)
