<!-- markdownlint-disable MD033 MD041 -->

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/assets/openshell-banner-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/brand/assets/openshell-banner-light.png">
  <img alt="OpenShell" src="docs/brand/assets/openshell-banner-light.png" width="430">
</picture>

<!-- markdownlint-enable MD033 MD041 -->

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-openshell-orange?logo=pypi)](https://pypi.org/project/openshell/)
[![Security Policy](https://img.shields.io/badge/Security-Report%20a%20Vulnerability-red)](SECURITY.md)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.nvidia.com/openshell/latest/index.html)
[![Project Status](https://img.shields.io/badge/status-alpha-orange)](https://github.com/NVIDIA/OpenShell/releases)

> [!IMPORTANT]
> **New in OpenShell 0.1.0:** a stable release cadence, new isolation primitives, an expanded extension surface, and new APIs. [Read the 0.1.0 upgrade guide](https://docs.nvidia.com/openshell/latest/upgrade/0-1-0).

OpenShell is the safe, private runtime for autonomous AI agents. It runs agents in sandboxes that protect your data, credentials, and infrastructure, governed by declarative YAML policies that prevent unauthorized file access, data exfiltration, and uncontrolled network activity.

## How It Works

A gateway control plane manages sandbox lifecycle through a compute driver: Docker, Podman, MicroVM, or Kubernetes. Inside each sandbox, a trusted supervisor launches the agent workload with filesystem and process restrictions, and routes all of its network traffic through a policy-enforcing proxy. For every outbound request, the proxy does one of three things:

- **Allows** it when the destination and calling binary match a network policy.
- **Binds credentials** to it: the agent only sees placeholders, and the proxy substitutes real provider credentials after policy admits a request to a profile-authorized endpoint.
- **Denies** it and logs the decision.

Filesystem and process policy are locked when the sandbox is created. Network policy and provider attachments can be updated on a running sandbox. See [Architecture](https://docs.nvidia.com/openshell/latest/about/architecture).

## Quickstart

You need Linux, macOS on Apple Silicon, or Windows with WSL 2 (experimental), plus Docker, Podman, or host virtualization. See the [Support Matrix](https://docs.nvidia.com/openshell/latest/about/support-matrix) for details.

```shell
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh
openshell sandbox create --name demo
```

The installer sets up the CLI and a local gateway. The default sandbox image is minimal Ubuntu with no agent installed. To run a real agent, follow [Run Your First Agent](https://docs.nvidia.com/openshell/latest/about/run-your-first-agent) to pick an image, attach providers, and write a policy.

## Policy in Action

Sandboxes start with minimal outbound access. This read-only GitHub rule lets `curl` fetch from the API but blocks writes, and applies without restarting the sandbox:

```shell
sandbox$ curl -sS https://api.github.com/zen
curl: (56) Received HTTP code 403 from proxy after CONNECT

$ openshell policy update demo --rule-name github_api --binary /usr/bin/curl \
    --add-endpoint api.github.com:443:read-only:rest:enforce --wait

sandbox$ curl -sS https://api.github.com/zen
Anything added dilutes everything else.
sandbox$ curl -sS -X POST https://api.github.com/repos/octocat/hello-world/issues -d '{"title":"oops"}'
{...,"error":"policy_denied",...,"policy":"github_api",...,"rule":"POST /repos/octocat/hello-world/issues",...}
```

Walk through it in the [First Network Policy tutorial](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy), or run `bash examples/sandbox-policy-quickstart/demo.sh`.

## Explore Further

- [Custom images](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview): bring your own container image with `--from`. See the [BYOC example](examples/bring-your-own-container).
- [Runtimes and GPUs](https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/runtimes): choose a compute driver and request GPUs with `--gpu`.
- [Providers](https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview) and [inference](https://docs.nvidia.com/openshell/latest/how-it-works/inference): give agents endpoint-bound access to model APIs and other services.
- [Policies](https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview): the full filesystem, network, and process policy model.
- [Kubernetes](https://docs.nvidia.com/openshell/latest/kubernetes/setup) (experimental): deploy the gateway with Helm. Your cluster CNI must enforce `NetworkPolicy` for sandbox isolation.
- [Prerelease and development builds](https://docs.nvidia.com/openshell/latest/about/installation#prerelease-and-development-builds): try an upcoming release or the latest commit on `main`.
- Agent skills: install the public OpenShell skills for your coding agent with `npx skills add NVIDIA/OpenShell`. See [`skills/`](skills/).

## SDKs

SDKs connect applications to an OpenShell gateway. They do not install the CLI. Use the same OpenShell release for the SDK and the gateway when possible.

| Language | Install | Docs |
|---|---|---|
| Python | `uv add openshell` | [README](python/openshell/) |
| TypeScript | `npm install @nvidia/openshell-sdk` (GitHub Packages) | [README](sdk/typescript/README.md) |
| Go | `go get github.com/NVIDIA/OpenShell/sdk/go@latest` | [README](sdk/go/README.md) |
| Rust | Git dependency pinned to a release tag | [README](crates/openshell-sdk/README.md) |

## Community

- **Questions and discussion:** [GitHub Discussions](https://github.com/NVIDIA/OpenShell/discussions)
- **Bug reports and feature requests:** [GitHub Issues](https://github.com/NVIDIA/OpenShell/issues), using the issue templates
- **Security vulnerabilities:** follow [SECURITY.md](SECURITY.md). Do not open a GitHub issue.
- **Roadmap:** [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233) and the [RFC board](https://github.com/orgs/NVIDIA/projects/233/views/6)
- **Try it in the cloud:** [Brev Launchable](https://brev.nvidia.com/launchable/deploy/now?launchableID=env-3Ap3tL55zq4a8kew1AuW0FpSLsg)

OpenShell is built agent-first: it is developed with the same agent-driven workflows it enables. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and the contribution workflow, and [AGENTS.md](AGENTS.md) for the contributor agent skills and workflow chains.

## Telemetry

OpenShell collects anonymous telemetry, limited to operational categories and counts, to help improve the project. It does not collect sandbox names, hostnames, file paths, prompts, credentials, provider or model names, or user content. To disable it, set `OPENSHELL_TELEMETRY_ENABLED=false` on the gateway, or `server.telemetryEnabled=false` for Helm installs. You can also compile telemetry out entirely. See [Telemetry](https://docs.nvidia.com/openshell/latest/observability/telemetry) for details and the [community telemetry reports](telemetry/README.md) for published usage trends.

## Notice and Disclaimer

This software automatically retrieves, accesses or interacts with external materials. Those retrieved materials are not distributed with this software and are governed solely by separate terms, conditions and licenses. You are solely responsible for finding, reviewing and complying with all applicable terms, conditions, and licenses, and for verifying the security, integrity and suitability of any retrieved materials for your specific use case. This software is provided "AS IS", without warranty of any kind. The author makes no representations or warranties regarding any retrieved materials, and assumes no liability for any losses, damages, liabilities or legal consequences from your use or inability to use this software or any retrieved materials. Use this software and the retrieved materials at your own risk.

## License

This project is licensed under the [Apache License 2.0](https://github.com/NVIDIA/OpenShell/blob/main/LICENSE).
