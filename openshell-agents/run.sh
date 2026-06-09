#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
AGENT_ARG="${OPENSHELL_AGENT_DIR:-}"
GATEWAY_OVERRIDE=""
SANDBOX_NAME_OVERRIDE=""
SANDBOX_FROM_OVERRIDE=""
HARNESS_OVERRIDE="${GATOR_HARNESS:-}"
GITHUB_PROVIDER_OVERRIDE="${GATOR_GITHUB_PROVIDER:-}"
CODEX_PROVIDER_OVERRIDE="${GATOR_CODEX_PROVIDER:-}"
CODEX_PROVIDER_PROFILE_OVERRIDE="${GATOR_CODEX_PROVIDER_PROFILE:-}"
CODEX_ACCESS_KEY_OVERRIDE="${GATOR_CODEX_ACCESS_CREDENTIAL_KEY:-}"
CODEX_LOCAL_BIN="${GATOR_CODEX_LOCAL_BIN:-}"
RUN_MODE_OVERRIDE="${OPENSHELL_AGENT_RUN_MODE:-}"
POLL_INTERVAL_OVERRIDE="${OPENSHELL_AGENT_POLL_INTERVAL_SECONDS:-}"
MAX_TRANSIENT_FAILURES_OVERRIDE="${OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES:-}"
RESET_REFRESH="${OPENSHELL_AGENT_RESET_REFRESH:-0}"
BACKGROUND=0
KEEP_SANDBOX=0

usage() {
    printf '%s\n' 'Usage: openshell-agents/run.sh --agent <name-or-path> [options] "agent prompt"'
    cat <<'EOF'

Options:
  --agent NAME|PATH       Agent manifest directory or name under openshell-agents/
  --gateway NAME          Gateway name to use
  --name NAME             Sandbox name
  --from DOCKERFILE|DIR   Local Dockerfile source for the sandbox image
  --harness NAME          Agent harness to run
  --github-provider NAME  Override the github-gator provider instance name
  --codex-provider NAME   Override the codex-gator provider instance name
  --codex-access-key KEY  Override the Codex access-token credential key
  --codex-bin PATH        Upload this Codex executable into the sandbox
  --once                  Run one bounded agent cycle
  --watch                 Keep the sandbox alive and re-run bounded cycles
  --poll-interval SECONDS Sleep duration between watch cycles
  --reset-refresh         Replace gateway-owned refresh material from host auth before rotating
  --background            Run sandbox create in the background and write a log
  --keep                  Keep the sandbox after the harness exits
  -h, --help              Show this help
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent)
            [[ $# -ge 2 ]] || fail "--agent requires a value"
            AGENT_ARG="$2"
            shift 2
            ;;
        --gateway)
            [[ $# -ge 2 ]] || fail "--gateway requires a value"
            GATEWAY_OVERRIDE="$2"
            shift 2
            ;;
        --name)
            [[ $# -ge 2 ]] || fail "--name requires a value"
            SANDBOX_NAME_OVERRIDE="$2"
            shift 2
            ;;
        --from)
            [[ $# -ge 2 ]] || fail "--from requires a value"
            SANDBOX_FROM_OVERRIDE="$2"
            shift 2
            ;;
        --harness)
            [[ $# -ge 2 ]] || fail "--harness requires a value"
            HARNESS_OVERRIDE="$2"
            shift 2
            ;;
        --github-provider)
            [[ $# -ge 2 ]] || fail "--github-provider requires a value"
            GITHUB_PROVIDER_OVERRIDE="$2"
            shift 2
            ;;
        --codex-provider)
            [[ $# -ge 2 ]] || fail "--codex-provider requires a value"
            CODEX_PROVIDER_OVERRIDE="$2"
            shift 2
            ;;
        --codex-access-key)
            [[ $# -ge 2 ]] || fail "--codex-access-key requires a value"
            CODEX_ACCESS_KEY_OVERRIDE="$2"
            shift 2
            ;;
        --codex-bin)
            [[ $# -ge 2 ]] || fail "--codex-bin requires a value"
            CODEX_LOCAL_BIN="$2"
            shift 2
            ;;
        --once)
            RUN_MODE_OVERRIDE="once"
            shift
            ;;
        --watch)
            RUN_MODE_OVERRIDE="watch"
            shift
            ;;
        --poll-interval)
            [[ $# -ge 2 ]] || fail "--poll-interval requires a value"
            POLL_INTERVAL_OVERRIDE="$2"
            shift 2
            ;;
        --reset-refresh)
            RESET_REFRESH=1
            shift
            ;;
        --background)
            BACKGROUND=1
            shift
            ;;
        --keep)
            KEEP_SANDBOX=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -* )
            fail "unknown option: $1"
            ;;
        *)
            break
            ;;
    esac
done

[[ -n "$AGENT_ARG" ]] || { usage >&2; exit 2; }
[[ $# -gt 0 ]] || { usage >&2; exit 2; }
USER_PROMPT="$*"

case "$AGENT_ARG" in
    /*|*/*)
        AGENT_DIR="$AGENT_ARG"
        ;;
    *)
        AGENT_DIR="$SCRIPT_DIR/$AGENT_ARG"
        ;;
esac

[[ -d "$AGENT_DIR" ]] || fail "missing agent directory: $AGENT_DIR"
AGENT_DIR="$(cd "$AGENT_DIR" && pwd)"
MANIFEST_FILE="$AGENT_DIR/agent.yaml"
[[ -f "$MANIFEST_FILE" ]] || fail "missing agent manifest: $MANIFEST_FILE"

require_cmd ruby
require_cmd "$OPENSHELL_BIN"

CONFIG_FILE="$(mktemp "${TMPDIR:-/tmp}/openshell-agent-config.XXXXXX")"
cleanup_config() {
    rm -f "$CONFIG_FILE"
}
trap cleanup_config EXIT

ruby -ryaml -rshellwords - "$MANIFEST_FILE" "$HARNESS_OVERRIDE" >"$CONFIG_FILE" <<'RUBY'
manifest = YAML.load_file(ARGV[0]) || {}
harness = ARGV[1].to_s.empty? ? manifest.dig("harness", "default").to_s : ARGV[1].to_s
supported = manifest.dig("harness", "supported") || {}
abort "unsupported harness: #{harness} (supported: #{supported.keys.join(', ')})" unless supported.key?(harness)

def sh(value)
  Shellwords.escape(value.to_s)
end

def emit(name, value)
  puts "#{name}=#{sh(value)}"
end

def emit_array(name, values)
  puts "#{name}=(#{values.map { |value| sh(value) }.join(' ')})"
end

harness_config = supported[harness] || {}
emit "AGENT_ID", manifest.fetch("id")
emit "AGENT_DISPLAY_NAME", manifest.fetch("display_name", manifest.fetch("id"))
emit "HARNESS", harness
emit "HARNESS_MODEL", harness_config.fetch("model", "")
emit "HARNESS_REASONING", harness_config.fetch("reasoning", "")
emit "SANDBOX_NAME_PREFIX", manifest.dig("sandbox", "name_prefix") || manifest.fetch("id")
emit "SANDBOX_FROM_DEFAULT", manifest.dig("sandbox", "from") || "agent://."
emit "GATEWAY_DEFAULT", manifest.dig("sandbox", "gateway") || "docker-dev"
emit "BACKGROUND_LOG_DIR", manifest.dig("sandbox", "background_log_dir") || "logs"
emit "PROMPT_TEMPLATE", manifest.fetch("prompt_template")
emit_array "PROFILE_PATHS", manifest.fetch("profile_paths", [])

runtime = manifest.fetch("runtime", {})
emit "RUNTIME_MODE", runtime.fetch("mode", "once")
emit "RUNTIME_POLL_INTERVAL_SECONDS", runtime.fetch("poll_interval_seconds", 900)
emit "RUNTIME_MAX_TRANSIENT_FAILURES", runtime.fetch("max_transient_failures", 5)

settings = manifest.fetch("settings", [])
emit "SETTING_COUNT", settings.length
settings.each_with_index do |setting, index|
  emit "SETTING_#{index}_KEY", setting.fetch("key")
  emit "SETTING_#{index}_VALUE", setting.fetch("value")
end

providers = manifest.fetch("providers", []).select do |provider|
  provider["harness"].nil? || provider["harness"] == harness
end
emit "PROVIDER_COUNT", providers.length
providers.each_with_index do |provider, index|
  emit "PROVIDER_#{index}_ID", provider.fetch("id")
  emit "PROVIDER_#{index}_NAME", provider.fetch("name")
  emit "PROVIDER_#{index}_PROFILE", provider.fetch("profile")
  emit "PROVIDER_#{index}_CREDENTIAL_MODE", provider.fetch("credential_mode", "explicit")
  credentials = provider.fetch("credentials", [])
  emit "PROVIDER_#{index}_CREDENTIAL_COUNT", credentials.length
  credentials.each_with_index do |credential, credential_index|
    source = credential.fetch("source", {})
    prefix = "PROVIDER_#{index}_CREDENTIAL_#{credential_index}"
    emit "#{prefix}_ENV", credential.fetch("env")
    emit "#{prefix}_EXPORT", credential.fetch("export", true)
    emit "#{prefix}_KIND", source.fetch("kind", "value")
    emit "#{prefix}_COMMAND", source.fetch("command", "")
    emit "#{prefix}_PATH", source.fetch("path", "")
    emit "#{prefix}_QUERY", source.fetch("query", "")
    emit "#{prefix}_VALUE", source.fetch("value", "")
  end

  refresh = provider["refresh"] || {}
  emit "PROVIDER_#{index}_REFRESH_ENABLED", refresh.empty? ? "false" : "true"
  emit "PROVIDER_#{index}_REFRESH_CREDENTIAL_KEY", refresh.fetch("credential_key", "")
  emit "PROVIDER_#{index}_REFRESH_STRATEGY", refresh.fetch("strategy", "")
  materials = refresh.fetch("materials", [])
  emit "PROVIDER_#{index}_REFRESH_MATERIAL_COUNT", materials.length
  materials.each_with_index do |material, material_index|
    source = material.fetch("source", {})
    prefix = "PROVIDER_#{index}_REFRESH_MATERIAL_#{material_index}"
    emit "#{prefix}_NAME", material.fetch("name")
    emit "#{prefix}_SECRET", material.fetch("secret", false)
    emit "#{prefix}_KIND", source.fetch("kind", material.key?("value") ? "value" : "")
    emit "#{prefix}_COMMAND", source.fetch("command", "")
    emit "#{prefix}_PATH", source.fetch("path", "")
    emit "#{prefix}_QUERY", source.fetch("query", "")
    emit "#{prefix}_VALUE", material.fetch("value", source.fetch("value", ""))
  end
end

uploads = []
manifest.fetch("skills", []).each do |skill|
  uploads << [skill.fetch("source"), skill.fetch("destination")]
end
manifest.fetch("subagents", []).each do |subagent|
  uploads << [subagent.fetch("source"), subagent.fetch("destination")]
end
emit "UPLOAD_COUNT", uploads.length
uploads.each_with_index do |(source, destination), index|
  emit "UPLOAD_#{index}_SOURCE", source
  emit "UPLOAD_#{index}_DESTINATION", destination
end
RUBY

# shellcheck source=/dev/null
source "$CONFIG_FILE"

set_var() {
    printf -v "$1" '%s' "$2"
}

resolve_manifest_path() {
    local path="$1"
    case "$path" in
        repo://*) printf '%s/%s' "$ROOT_DIR" "${path#repo://}" ;;
        agent://*) printf '%s/%s' "$AGENT_DIR" "${path#agent://}" ;;
        /*) printf '%s' "$path" ;;
        *) printf '%s/%s' "$AGENT_DIR" "$path" ;;
    esac
}

expand_home_path() {
    local path="$1"
    case "$path" in
        \~) printf '%s' "$HOME" ;;
        \~/*) printf '%s/%s' "$HOME" "${path#\~/}" ;;
        *) printf '%s' "$path" ;;
    esac
}

openshell_cmd() {
    "$OPENSHELL_BIN" --gateway "$GATEWAY" "$@"
}

upsert_provider() {
    local name="$1"
    local type="$2"
    shift 2

    if openshell_cmd provider get "$name" >/dev/null 2>&1; then
        openshell_cmd provider update "$name" "$@" >/dev/null
    else
        openshell_cmd provider create --name "$name" --type "$type" "$@" >/dev/null
    fi
}

import_provider_profile() {
    local profile_id="$1"
    local profile_file="$2"
    local import_output

    openshell_cmd provider profile delete "$profile_id" >/dev/null 2>&1 || true
    if import_output="$(openshell_cmd provider profile import --file "$profile_file" 2>&1)"; then
        return 0
    fi
    if [[ "$import_output" == *"already exists"* ]]; then
        echo "Provider profile already exists: $profile_file"
        return 0
    fi

    printf '%s\n' "$import_output" >&2
    return 1
}

resolve_profile_file() {
    local profile_id="$1"
    ruby -ryaml - "$MANIFEST_FILE" "$ROOT_DIR" "$AGENT_DIR" "$profile_id" <<'RUBY'
manifest_path, root_dir, agent_dir, profile_id = ARGV
manifest = YAML.load_file(manifest_path) || {}

def resolve(path, root_dir, agent_dir)
  case path.to_s
  when /^repo:\/\// then File.expand_path(path.delete_prefix("repo://"), root_dir)
  when /^agent:\/\// then File.expand_path(path.delete_prefix("agent://"), agent_dir)
  when /^\// then path
  else File.expand_path(path, agent_dir)
  end
end

selected = nil
manifest.fetch("profile_paths", []).each do |raw_path|
  dir = resolve(raw_path, root_dir, agent_dir)
  next unless File.directory?(dir)

  ids = {}
  Dir.glob(File.join(dir, "*.{yaml,yml}")).sort.each do |file|
    data = YAML.load_file(file) || {}
    id = data["id"]
    next if id.nil? || id.to_s.empty?
    if ids.key?(id)
      abort "duplicate provider profile id '#{id}' in #{dir}: #{ids[id]} and #{file}"
    end
    ids[id] = file
  rescue Psych::SyntaxError => error
    abort "invalid provider profile YAML #{file}: #{error.message}"
  end

  match = ids[profile_id]
  next unless match
  if selected
    warn "warning: provider profile #{profile_id} in #{match} is shadowed by #{selected}"
  else
    selected = match
  end
end

abort "provider profile not found in profile_paths: #{profile_id}" unless selected
puts selected
RUBY
}

resolve_source_value() {
    local kind="$1"
    local command_value="$2"
    local path_value="$3"
    local query_value="$4"
    local literal_value="$5"

    case "$kind" in
        host_command)
            bash -lc "$command_value"
            ;;
        file_json)
            local expanded_path
            expanded_path="$(expand_home_path "$path_value")"
            [[ -f "$expanded_path" ]] || fail "missing credential file: $expanded_path"
            ruby -rjson - "$expanded_path" "$query_value" <<'RUBY'
path, query = ARGV
value = JSON.parse(File.read(path))
query.split(".").each do |part|
  value = value.fetch(part)
end
print value.to_s
RUBY
            ;;
        value)
            printf '%s' "$literal_value"
            ;;
        *)
            fail "unsupported credential source kind: $kind"
            ;;
    esac
}

configure_provider_refresh() {
    local provider_index="$1"
    local provider_name_var="PROVIDER_${provider_index}_NAME"
    local key_var="PROVIDER_${provider_index}_REFRESH_CREDENTIAL_KEY"
    local strategy_var="PROVIDER_${provider_index}_REFRESH_STRATEGY"
    local count_var="PROVIDER_${provider_index}_REFRESH_MATERIAL_COUNT"
    local provider_name="${!provider_name_var}"
    local credential_key="${!key_var}"
    local strategy="${!strategy_var}"
    local material_count="${!count_var}"
    local args=(
        provider refresh configure "$provider_name"
        --credential-key "$credential_key"
        --strategy "$strategy"
    )

    local material_index
    for ((material_index = 0; material_index < material_count; material_index++)); do
        local prefix="PROVIDER_${provider_index}_REFRESH_MATERIAL_${material_index}"
        local name_var="${prefix}_NAME"
        local secret_var="${prefix}_SECRET"
        local kind_var="${prefix}_KIND"
        local command_var="${prefix}_COMMAND"
        local path_var="${prefix}_PATH"
        local query_var="${prefix}_QUERY"
        local value_var="${prefix}_VALUE"
        local material_name="${!name_var}"
        local material_value

        if [[ "$material_name" == "client_id" && -n "${GATOR_CODEX_OAUTH_CLIENT_ID:-}" ]]; then
            material_value="$GATOR_CODEX_OAUTH_CLIENT_ID"
        else
            material_value="$(resolve_source_value "${!kind_var}" "${!command_var}" "${!path_var}" "${!query_var}" "${!value_var}")"
        fi
        [[ -n "$material_value" ]] || fail "empty refresh material: $provider_name/$material_name"
        args+=(--material "$material_name=$material_value")
        if [[ "${!secret_var}" == "true" ]]; then
            args+=(--secret-material-key "$material_name")
        fi
    done

    local status_output
    local rotate_output
    status_output="$(openshell_cmd provider refresh status "$provider_name" --credential-key "$credential_key" 2>&1 || true)"
    if [[ "$RESET_REFRESH" != "1" && "$status_output" != *"No refresh configuration found"* ]]; then
        echo "Preserving existing gateway refresh state for $provider_name/$credential_key. Use --reset-refresh to replace it from host auth."
    else
        openshell_cmd "${args[@]}" >/dev/null
        echo "Configured gateway refresh for $provider_name/$credential_key."
    fi
    if ! rotate_output="$(openshell_cmd provider refresh rotate "$provider_name" --credential-key "$credential_key" 2>&1)"; then
        if [[ "$RESET_REFRESH" != "1" && "$status_output" != *"No refresh configuration found"* ]]; then
            echo "Gateway refresh rotation failed; resetting $provider_name/$credential_key from host auth and retrying once." >&2
            openshell_cmd "${args[@]}" >/dev/null
            openshell_cmd provider refresh rotate "$provider_name" --credential-key "$credential_key" >/dev/null
        else
            printf '%s\n' "$rotate_output" >&2
            return 1
        fi
    fi
    echo "Rotated gateway refresh credential for $provider_name/$credential_key."
}

GATEWAY="${GATEWAY_OVERRIDE:-${GATOR_GATEWAY:-$GATEWAY_DEFAULT}}"
SANDBOX_NAME="${SANDBOX_NAME_OVERRIDE:-${GATOR_SANDBOX_NAME:-$SANDBOX_NAME_PREFIX-$(date +%Y%m%d%H%M%S)}}"
SANDBOX_FROM="${SANDBOX_FROM_OVERRIDE:-${GATOR_SANDBOX_FROM:-$(resolve_manifest_path "$SANDBOX_FROM_DEFAULT")}}"
RUN_MODE="${RUN_MODE_OVERRIDE:-$RUNTIME_MODE}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_OVERRIDE:-$RUNTIME_POLL_INTERVAL_SECONDS}"
MAX_TRANSIENT_FAILURES="${MAX_TRANSIENT_FAILURES_OVERRIDE:-$RUNTIME_MAX_TRANSIENT_FAILURES}"

case "$RUN_MODE" in
    once|watch) ;;
    *) fail "unsupported runtime mode: $RUN_MODE" ;;
esac
[[ "$POLL_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || fail "--poll-interval must be an integer number of seconds"
[[ "$MAX_TRANSIENT_FAILURES" =~ ^[0-9]+$ ]] || fail "max_transient_failures must be an integer"
[[ "$POLL_INTERVAL_SECONDS" -gt 0 ]] || fail "--poll-interval must be greater than zero"

for ((provider_index = 0; provider_index < PROVIDER_COUNT; provider_index++)); do
    profile_var="PROVIDER_${provider_index}_PROFILE"
    name_var="PROVIDER_${provider_index}_NAME"
    refresh_key_var="PROVIDER_${provider_index}_REFRESH_CREDENTIAL_KEY"
    case "${!profile_var}" in
        github-gator)
            [[ -z "$GITHUB_PROVIDER_OVERRIDE" ]] || set_var "$name_var" "$GITHUB_PROVIDER_OVERRIDE"
            ;;
        codex-gator)
            [[ -z "$CODEX_PROVIDER_OVERRIDE" ]] || set_var "$name_var" "$CODEX_PROVIDER_OVERRIDE"
            [[ -z "$CODEX_PROVIDER_PROFILE_OVERRIDE" ]] || set_var "$profile_var" "$CODEX_PROVIDER_PROFILE_OVERRIDE"
            [[ -z "$CODEX_ACCESS_KEY_OVERRIDE" ]] || set_var "$refresh_key_var" "$CODEX_ACCESS_KEY_OVERRIDE"
            ;;
    esac
done

PAYLOAD_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent.XXXXXX")"
PAYLOAD_DIR="$PAYLOAD_PARENT/payload"
PAYLOAD_IMAGE_DIR="/etc/openshell/agent-payload"
cleanup_payload() {
    rm -rf "$PAYLOAD_PARENT"
}
trap 'cleanup_config; cleanup_payload' EXIT

mkdir -p "$PAYLOAD_DIR"
cp -R "$SCRIPT_DIR/runtime" "$PAYLOAD_DIR/runtime"
chmod +x "$PAYLOAD_DIR/runtime"/*.sh
chmod +x "$PAYLOAD_DIR/runtime/harnesses/$HARNESS"/*.sh

if [[ -n "$CODEX_LOCAL_BIN" ]]; then
    [[ -x "$CODEX_LOCAL_BIN" ]] || fail "--codex-bin is not executable: $CODEX_LOCAL_BIN"
    [[ "$HARNESS" == "codex" ]] || fail "--codex-bin is only valid with --harness codex"
    cp "$CODEX_LOCAL_BIN" "$PAYLOAD_DIR/runtime/harnesses/codex/codex"
    chmod +x "$PAYLOAD_DIR/runtime/harnesses/codex/codex"
fi

for ((upload_index = 0; upload_index < UPLOAD_COUNT; upload_index++)); do
    source_var="UPLOAD_${upload_index}_SOURCE"
    destination_var="UPLOAD_${upload_index}_DESTINATION"
    source_path="$(resolve_manifest_path "${!source_var}")"
    destination_path="$PAYLOAD_DIR/${!destination_var}"
    [[ -f "$source_path" ]] || fail "missing payload source: $source_path"
    mkdir -p "$(dirname "$destination_path")"
    cp "$source_path" "$destination_path"
done

SUBAGENT_COMMAND="bash $PAYLOAD_IMAGE_DIR/runtime/subagent.sh principal-engineer-reviewer < task.md"
PROMPT_TEMPLATE_PATH="$(resolve_manifest_path "$PROMPT_TEMPLATE")"
[[ -f "$PROMPT_TEMPLATE_PATH" ]] || fail "missing prompt template: $PROMPT_TEMPLATE_PATH"
ruby - "$PROMPT_TEMPLATE_PATH" "$PAYLOAD_DIR/agent-prompt.md" "$HARNESS" "$SUBAGENT_COMMAND" "$RUN_MODE" "$POLL_INTERVAL_SECONDS" "$USER_PROMPT" <<'RUBY'
template_path, output_path, harness, subagent_command, run_mode, poll_interval_seconds, user_prompt = ARGV
values = {
  "HARNESS" => harness,
  "SUBAGENT_COMMAND" => subagent_command,
  "RUN_MODE" => run_mode,
  "POLL_INTERVAL_SECONDS" => poll_interval_seconds,
  "USER_PROMPT" => user_prompt,
}
template = File.read(template_path)
rendered = template.gsub(/\{\{([A-Z0-9_]+)\}\}/) do
  values.fetch(Regexp.last_match(1))
end
File.write(output_path, rendered)
RUBY

prepare_immutable_sandbox_source() {
    local source="$1"
    local dockerfile
    local context

    if [[ -f "$source" ]]; then
        local lower_name
        lower_name="$(basename "$source" | tr '[:upper:]' '[:lower:]')"
        [[ "$lower_name" == *dockerfile* || "$lower_name" == *.dockerfile ]] || fail "immutable agent payload requires --from to be a Dockerfile path or directory: $source"
        dockerfile="$(cd "$(dirname "$source")" && pwd)/$(basename "$source")"
        context="$(cd "$(dirname "$source")" && pwd)"
    elif [[ -d "$source" && -f "$source/Dockerfile" ]]; then
        context="$(cd "$source" && pwd)"
        dockerfile="$context/Dockerfile"
    else
        fail "immutable agent payload requires a local Dockerfile source; --from '$source' cannot receive read-only agent guts"
    fi

    local build_context="$PAYLOAD_PARENT/build-context"
    mkdir -p "$build_context"
    (
        cd "$context"
        tar --exclude './gator/logs' --exclude './logs' -cf - .
    ) | (
        cd "$build_context"
        tar -xf -
    )

    rm -rf "$build_context/openshell-agent-payload"
    mkdir -p "$build_context/openshell-agent-payload"
    cp -R "$PAYLOAD_DIR/." "$build_context/openshell-agent-payload/"

    if [[ -L "$build_context/.dockerignore" ]]; then
        rm -f "$build_context/.dockerignore"
    fi

    {
        printf '\n# OpenShell staged immutable agent payload\n'
        printf '!openshell-agent-payload\n'
        printf '!openshell-agent-payload/**\n'
    } >> "$build_context/.dockerignore"

    local rel_dockerfile
    rel_dockerfile="${dockerfile#$context/}"
    local build_dockerfile="$build_context/$rel_dockerfile"
    [[ -f "$build_dockerfile" ]] || fail "failed to stage Dockerfile: $rel_dockerfile"
    [[ ! -L "$build_dockerfile" ]] || fail "staged Dockerfile must not be a symlink: $rel_dockerfile"

    ruby - "$build_dockerfile" "$PAYLOAD_IMAGE_DIR" <<'RUBY'
dockerfile_path, payload_image_dir = ARGV
lines = File.readlines(dockerfile_path)
final_stage_start = lines.rindex { |line| line.strip.start_with?("FROM ") } || 0
final_user = lines[final_stage_start..].reverse.find { |line| line.strip.start_with?("USER ") }&.strip
File.open(dockerfile_path, "a") do |file|
  file.puts
  file.puts "USER root"
  file.puts "COPY openshell-agent-payload/ #{payload_image_dir}/"
  file.puts "RUN chmod -R a-w #{payload_image_dir}"
  file.puts final_user if final_user
end
RUBY

    SANDBOX_FROM="$build_dockerfile"
}

prepare_immutable_sandbox_source "$SANDBOX_FROM"

for ((setting_index = 0; setting_index < SETTING_COUNT; setting_index++)); do
    key_var="SETTING_${setting_index}_KEY"
    value_var="SETTING_${setting_index}_VALUE"
    openshell_cmd settings set --global --key "${!key_var}" --value "${!value_var}" --yes >/dev/null
done

PROVIDER_ARGS=()
for ((provider_index = 0; provider_index < PROVIDER_COUNT; provider_index++)); do
    name_var="PROVIDER_${provider_index}_NAME"
    profile_var="PROVIDER_${provider_index}_PROFILE"
    mode_var="PROVIDER_${provider_index}_CREDENTIAL_MODE"
    credential_count_var="PROVIDER_${provider_index}_CREDENTIAL_COUNT"
    refresh_enabled_var="PROVIDER_${provider_index}_REFRESH_ENABLED"
    provider_name="${!name_var}"
    profile_id="${!profile_var}"
    credential_mode="${!mode_var}"
    credential_count="${!credential_count_var}"
    profile_file="$(resolve_profile_file "$profile_id")"

    import_provider_profile "$profile_id" "$profile_file"

    credential_args=()
    for ((credential_index = 0; credential_index < credential_count; credential_index++)); do
        prefix="PROVIDER_${provider_index}_CREDENTIAL_${credential_index}"
        env_var="${prefix}_ENV"
        export_var="${prefix}_EXPORT"
        kind_var="${prefix}_KIND"
        command_var="${prefix}_COMMAND"
        path_var="${prefix}_PATH"
        query_var="${prefix}_QUERY"
        value_var="${prefix}_VALUE"
        credential_env="${!env_var}"
        credential_value="$(resolve_source_value "${!kind_var}" "${!command_var}" "${!path_var}" "${!query_var}" "${!value_var}")"
        [[ -n "$credential_value" ]] || fail "empty credential value: $provider_name/$credential_env"
        if [[ "${!export_var}" == "true" ]]; then
            export "$credential_env=$credential_value"
        fi
        if [[ "$credential_mode" == "explicit" ]]; then
            credential_args+=(--credential "$credential_env")
        fi
    done

    case "$credential_mode" in
        explicit)
            upsert_provider "$provider_name" "$profile_id" "${credential_args[@]}"
            ;;
        from_existing)
            upsert_provider "$provider_name" "$profile_id" --from-existing
            ;;
        *)
            fail "unsupported credential_mode for $provider_name: $credential_mode"
            ;;
    esac

    if [[ "${!refresh_enabled_var}" == "true" ]]; then
        configure_provider_refresh "$provider_index"
    fi
    PROVIDER_ARGS+=(--provider "$provider_name")
done

KEEP_ARGS=()
if [[ "$KEEP_SANDBOX" != "1" ]]; then
    KEEP_ARGS+=(--no-keep)
fi

HARNESS_ENV_ARGS=(
    "OPENSHELL_AGENT_ID=$AGENT_ID"
    "OPENSHELL_AGENT_HARNESS=$HARNESS"
    "OPENSHELL_AGENT_RUN_MODE=$RUN_MODE"
    "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS=$POLL_INTERVAL_SECONDS"
    "OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES=$MAX_TRANSIENT_FAILURES"
)

case "$HARNESS" in
    codex)
        HARNESS_ENV_ARGS+=(
            "CODEX_MODEL=${CODEX_MODEL:-$HARNESS_MODEL}"
            "CODEX_REASONING=${CODEX_REASONING:-$HARNESS_REASONING}"
        )
        ;;
esac

SANDBOX_CMD=(
    env -u OPENSHELL_SANDBOX_POLICY
    "$OPENSHELL_BIN" --gateway "$GATEWAY" sandbox create
    --name "$SANDBOX_NAME"
    --from "$SANDBOX_FROM"
    "${PROVIDER_ARGS[@]}"
    --no-git-ignore
    --no-auto-providers
    --no-tty
    "${KEEP_ARGS[@]}"
    -- env "${HARNESS_ENV_ARGS[@]}" bash "$PAYLOAD_IMAGE_DIR/runtime/entrypoint.sh"
)

echo "Launching $AGENT_DISPLAY_NAME sandbox '$SANDBOX_NAME' on gateway '$GATEWAY'..."
if [[ "$BACKGROUND" == "1" ]]; then
    LOG_DIR="$(resolve_manifest_path "$BACKGROUND_LOG_DIR")"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/${SANDBOX_NAME}.log"
    trap - EXIT
    (
        trap 'cleanup_config; cleanup_payload' EXIT
        "${SANDBOX_CMD[@]}"
    ) >"$LOG_FILE" 2>&1 &
    echo "Started in background. Log: $LOG_FILE"
else
    "${SANDBOX_CMD[@]}"
fi
