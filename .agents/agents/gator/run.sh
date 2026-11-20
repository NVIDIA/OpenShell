#!/usr/bin/env bash

set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$AGENT_DIR/../../.." && pwd)"

exec bash "$ROOT_DIR/scripts/agents/run.sh" --agent "$AGENT_DIR" "$@"
