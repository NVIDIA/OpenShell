#!/usr/bin/env bash

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/repo/.agents/agents/gator" "$tmp/repo/scripts/agents"
cp "$AGENT_DIR/run.sh" "$tmp/repo/.agents/agents/gator/run.sh"
cat > "$tmp/repo/scripts/agents/run.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" > "$CAPTURE_ARGS"
pwd > "$CAPTURE_CWD"
SH

prompt='Review PR #5723; keep $(literal) and "quotes" unchanged'
(
    cd "$tmp"
    CAPTURE_ARGS="$tmp/args" CAPTURE_CWD="$tmp/cwd" \
        bash "$tmp/repo/.agents/agents/gator/run.sh" --once --name gtr-test "$prompt"
)
mapfile -d '' -t arguments < "$tmp/args"
expected=(--agent "$tmp/repo/.agents/agents/gator" --once --name gtr-test "$prompt")
[[ "${#arguments[@]}" == "${#expected[@]}" ]]
for index in "${!expected[@]}"; do
    [[ "${arguments[$index]}" == "${expected[$index]}" ]]
done
[[ "$(cat "$tmp/cwd")" == "$tmp" ]]
bash "$AGENT_DIR/run.sh" --help | grep -Fq '.agents/agents/'
echo 'ok - Gator entry point resolves its bundle and forwards literal arguments from any directory'
