---
title: OPENSHELL
section: 1
header: OpenShell Manual
footer: openshell
date: 2025
---

# NAME

openshell - CLI for managing OpenShell sandboxes, gateways, and providers

# SYNOPSIS

**openshell** \[*OPTIONS*\] *COMMAND* \[*ARGS*\]

# DESCRIPTION

**openshell** is the command-line interface for OpenShell, a platform
providing safe, sandboxed runtimes for autonomous AI agents. It manages
the gateway control plane, sandbox lifecycle, credential providers,
network policies, and inference routing.

The CLI communicates with a gateway server over gRPC. The gateway can
run as a systemd user service (RPM deployment with Podman driver), a
Docker container with embedded K3s, or behind a cloud reverse proxy.

# COMMANDS

## Gateway Management

**gateway start**
:   Deploy a new gateway using Docker (not applicable to RPM deployments;
    use **systemctl --user start openshell-gateway** instead).

**gateway stop**
:   Stop a Docker-managed gateway (use **systemctl --user stop
    openshell-gateway** for RPM deployments).

**gateway destroy** \[**--name** *NAME*\]
:   Destroy a gateway. For RPM deployments, this removes the CLI
    registration only.

**gateway add** *ENDPOINT* \[**--local**\] \[**--name** *NAME*\] \[**--remote** *USER@HOST*\]
:   Register an existing gateway with the CLI.

**gateway select** \[*NAME*\]
:   List registered gateways or switch the active gateway.

**gateway info** \[**--name** *NAME*\]
:   Show deployment details for a gateway.

**gateway login**
:   Re-authenticate with a cloud gateway.

**status**
:   Check the health of the active gateway.

## Sandbox Management

**sandbox create** \[**--from** *IMAGE*\] \[**--policy** *FILE*\] \[**--provider** *NAME*\] \[**--gpu**\] \[**--upload** *SRC:DST*\] \[**--forward** *PORT*\] \[**--** *COMMAND*\]
:   Create a new sandbox. If no gateway exists, auto-bootstraps one
    (Docker mode only).

**sandbox list** \[**--selector** *LABEL*\]
:   List all sandboxes on the active gateway.

**sandbox get** *NAME*
:   Show details for a sandbox.

**sandbox delete** *NAME* \| **--all**
:   Delete one or all sandboxes.

**sandbox connect** *NAME* \[**--editor** *EDITOR*\]
:   SSH into a running sandbox.

**sandbox exec** **-n** *NAME* \[**--workdir** *DIR*\] **--** *COMMAND*
:   Execute a command in a sandbox.

**sandbox upload** *NAME* *LOCAL* *REMOTE*
:   Upload files to a sandbox.

**sandbox download** *NAME* *REMOTE* *LOCAL*
:   Download files from a sandbox.

## Policy Management

**policy get** *SANDBOX* \[**--full**\]
:   Show the active policy for a sandbox.

**policy set** *SANDBOX* **--policy** *FILE* \[**--wait**\]
:   Apply a policy to a sandbox.

**policy update** *SANDBOX* \[**--add-endpoint** *SPEC*\] \[**--add-allow** *RULE*\]
:   Incrementally update a sandbox policy.

**policy list** *SANDBOX*
:   Show policy revision history.

**policy prove** **--policy** *FILE* \[**--credentials** *FILE*\]
:   Verify policy properties.

## Provider Management

**provider create** **--name** *NAME* **--type** *TYPE* \[**--from-existing**\] \[**--credential** *KEY=VALUE*\]
:   Create a credential provider.

**provider list**
:   List all providers.

**provider get** *NAME*
:   Show provider details.

**provider update** *NAME* \[**--from-existing**\] \[**--credential** *KEY=VALUE*\]
:   Update provider credentials.

**provider delete** *NAME*
:   Delete a provider.

## Inference Routing

**inference set** **--provider** *NAME* **--model** *MODEL*
:   Configure inference routing.

**inference get**
:   Show current inference configuration.

**inference update** \[**--model** *MODEL*\]
:   Update inference configuration.

## Other

**logs** *SANDBOX* \[**--tail**\]
:   View sandbox logs.

**forward start** *PORT* *SANDBOX* \[**-d**\]
:   Start port forwarding to a sandbox.

**forward stop** *PORT*
:   Stop port forwarding.

**forward list**
:   List active port forwards.

**term**
:   Open the real-time TUI dashboard.

**doctor check** \| **logs** \| **exec** \| **llm.txt**
:   Diagnostic tools (Docker/K3s mode only; see **TROUBLESHOOTING**
    section for RPM alternatives).

**completions** *SHELL*
:   Generate shell completions (bash, zsh, fish).

# GLOBAL OPTIONS

**-g**, **--gateway** *NAME*
:   Target a specific gateway by name.

**--gateway-endpoint** *URL*
:   Connect to a gateway by URL directly.

**-h**, **--help**
:   Print help information.

**-V**, **--version**
:   Print version.

# ENVIRONMENT

**OPENSHELL_GATEWAY**
:   Default gateway name (overrides active gateway).

**OPENSHELL_GATEWAY_ENDPOINT**
:   Direct gateway URL (bypasses metadata lookup).

**ANTHROPIC_API_KEY**, **OPENAI_API_KEY**, **OPENROUTER_API_KEY**
:   API keys discovered by auto-provider creation.

**GITHUB_TOKEN**, **GH_TOKEN**
:   GitHub credentials for provider auto-discovery.

# FILES

*~/.config/openshell/gateways/*
:   Gateway metadata and mTLS certificates.

*~/.config/openshell/active_gateway*
:   Name of the currently active gateway.

# EXAMPLES

Register the local RPM gateway and create a sandbox:

    openshell gateway add --local https://127.0.0.1:8080
    openshell sandbox create -- claude

List sandboxes and connect to one:

    openshell sandbox list
    openshell sandbox connect my-sandbox

Create a provider from a local environment variable:

    openshell provider create --name openai --type openai --from-existing

Check gateway health:

    openshell status

# SEE ALSO

**openshell-gateway**(8), **openshell-gateway.env**(5)

Full documentation: *https://docs.nvidia.com/openshell/*

Run **openshell** *COMMAND* **--help** for detailed help on any command.
