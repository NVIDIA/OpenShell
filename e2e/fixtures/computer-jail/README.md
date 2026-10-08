# Computer jail acceptance (33.03.03)

Run this fixture as the supervisor's ordinary process entrypoint, with protocol v3
launcher enabled and the policy in this folder. It proves a command longer than
five seconds, child processes, Python/Node/git, asyncio, the private filesystem
boundary, read-only skills, internet socket denial, output caps, timeout kills, and cleanup when a turn disconnects.
The companion computer-spike fixture proves Office/browser feasibility separately.

The container must start the supervisor as root with SYS_ADMIN and an outer
seccomp profile that permits namespace setup. The supervisor prepares a private
full procfs, then starts the launcher as UID/GID 10001 without capabilities. The
workload and jailed shell remain non-root. Landlock is mandatory.

On Docker Desktop, copy the fixture into the container's Linux filesystem before
launching the supervisor: Landlock does not reliably cover Mac-host bind-mount
files. Mount the source at `/source-fixture`, copy it to `/fixture`, create and
chown `/sandbox` to 10001, then run:

```sh
OPENSHELL_EXPERIMENTAL_BWRAP_LAUNCHER=1 /openshell-sandbox \
  --mode process --policy-rules /fixture-policy.rego \
  --policy-data /fixture/policy.yaml -- /bin/sh /fixture/run.sh
cat /tmp/computer-jail-result.log
```

Use the supervisor network crate's `data/sandbox-policy.rego` as the policy rules.
A successful run prints `{"computer_jail": "passed", "uid": 10001}`. The computer
image supplies system Python, Node and git under `/usr`, separately from the
runtime's `/app/.venv`.
