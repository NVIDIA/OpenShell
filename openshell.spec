# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

%global crate openshell

# Cargo/Rust builds with vendored deps do not produce debugsource listings
# in the format redhat-rpm-config expects (especially on EPEL).
%global debug_package %{nil}

Name:           openshell
Version:        0.0.37
Release:        1.20260428105655427965.rpm.25.gee990b25%{?dist}
Summary:        Safe, sandboxed runtimes for autonomous AI agents

License:        Apache-2.0
URL:            https://github.com/NVIDIA/OpenShell
Source0: openshell-0.0.37.tar.gz
Source1: openshell-0.0.37-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64

# Rust build dependencies
# NOTE: MSRV is 1.88 (Rust edition 2024). As of mid-2025, this requires
# Fedora Rawhide or newer. Stable Fedora and EPEL-10 may ship older Rust;
# adjust targets in .packit.yaml accordingly or provide a supplementary
# Rust toolchain via additional_repos in the COPR build config.
BuildRequires:  rust >= 1.88
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  cmake
BuildRequires:  pkg-config
BuildRequires:  clang-devel
BuildRequires:  z3-devel
BuildRequires:  systemd-rpm-macros

# Python sub-package build dependencies
BuildRequires:  python3-devel

# Runtime: container runtime for gateway lifecycle (start/stop/destroy).
# Podman is preferred; Docker is also supported via --container-runtime flag.
Recommends:     podman

%description
OpenShell provides safe, sandboxed runtimes for autonomous AI agents.
It offers a CLI for managing gateways, sandboxes, and providers with
policy-enforced egress routing, credential proxying, and privacy-aware
LLM inference routing.

# --- Gateway sub-package ---
%package gateway
Summary:        OpenShell gateway server with Podman sandbox driver
Requires:       podman
Requires:       %{name} = %{version}-%{release}

%description gateway
OpenShell gateway server providing the control-plane API for sandbox
lifecycle management. This package configures the gateway to use the
Podman compute driver, pulling sandbox and supervisor images from
ghcr.io/nvidia/openshell.

# --- Python SDK sub-package ---
%package -n python3-%{name}
Summary:        OpenShell Python SDK for agent execution and management
# Use Recommends instead of Requires because Fedora 43+ ships older
# versions of grpcio (1.48) and protobuf (3.19) than the SDK needs.
# Users on distros with older packages can install these via pip/uv.
Recommends:     python3-cloudpickle >= 3.0
Recommends:     python3-grpcio >= 1.60
Recommends:     python3-protobuf >= 4.25
Recommends:     %{name}

%description -n python3-%{name}
Python SDK for OpenShell providing programmatic access to sandbox
management, agent execution, and inference routing via gRPC.

%prep
%autosetup -n %{name}-%{version}

# Extract vendored Cargo dependencies
tar xf %{SOURCE1}

# Configure Cargo to use vendored dependencies for offline build
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

# Patch workspace version from placeholder to actual version
sed -i 's/^version = "0.0.0"/version = "%{version}"/' Cargo.toml
grep -q 'version = "%{version}"' Cargo.toml || (echo "ERROR: Cargo.toml version patch failed" && exit 1)

%build
# Build the CLI and gateway binaries
export CARGO_BUILD_JOBS=%{_smp_build_ncpus}
# Set the default container image tag so compiled-in image refs point at
# real tags in the ghcr.io/nvidia/openshell registry.
export OPENSHELL_IMAGE_TAG=latest
cargo build --release --bin openshell --bin openshell-gateway

%install
# --- CLI binary ---
install -Dpm 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# --- Gateway binary ---
install -Dpm 0755 target/release/%{name}-gateway %{buildroot}%{_bindir}/%{name}-gateway

# --- Gateway systemd unit ---
install -d %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/%{name}-gateway.service << 'EOF'
[Unit]
Description=OpenShell Gateway
Documentation=https://github.com/NVIDIA/OpenShell
After=network-online.target podman.socket
Wants=podman.socket

[Service]
Type=exec
EnvironmentFile=/etc/sysconfig/openshell-gateway
ExecStart=/usr/bin/openshell-gateway
StateDirectory=openshell
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

# --- Gateway systemd user unit (rootless Podman) ---
# Installed to the systemd user unit directory so any user can run:
#   systemctl --user start podman.socket
#   systemctl --user enable --now openshell-gateway.service
install -d %{buildroot}%{_userunitdir}
cat > %{buildroot}%{_userunitdir}/%{name}-gateway.service << 'EOF'
[Unit]
Description=OpenShell Gateway (user)
Documentation=https://github.com/NVIDIA/OpenShell
After=podman.socket
Wants=podman.socket

[Service]
Type=exec
# Self-contained defaults for rootless operation.
#
# WARNING: TLS is disabled. The gateway has NO authentication and
# listens on all interfaces. For network-exposed setups, configure
# mTLS certificates and remove OPENSHELL_DISABLE_TLS.
#
# The SSH handshake secret is auto-generated on first start into
# ~/.config/openshell/gateway.env (mode 0600). To override, edit
# that file or use: systemctl --user edit openshell-gateway.service

# Auto-generate SSH handshake secret on first start if not present.
# %%E expands to $XDG_CONFIG_HOME (~/.config) in user units.
ExecStartPre=/bin/sh -c 'ENV=%%E/openshell/gateway.env; [ -f "$ENV" ] || { mkdir -p %%E/openshell && echo "OPENSHELL_SSH_HANDSHAKE_SECRET=$(od -An -tx1 -N32 /dev/urandom | tr -dc 0-9a-f)" > "$ENV" && chmod 600 "$ENV"; }'
EnvironmentFile=-%%E/openshell/gateway.env
Environment=OPENSHELL_DRIVERS=podman
Environment=OPENSHELL_DB_URL=sqlite://%%S/openshell/gateway.db
Environment=OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:latest
Environment=OPENSHELL_SANDBOX_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest
Environment=OPENSHELL_DISABLE_TLS=true
ExecStart=/usr/bin/openshell-gateway
StateDirectory=openshell
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=default.target
EOF

# --- Gateway environment file ---
# Provides defaults for the Podman driver and GHCR image references.
# Mode 0640: contains the SSH handshake secret -- must not be world-readable.
# Admins can override these values by editing this file.
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -pm 0640 /dev/null %{buildroot}%{_sysconfdir}/sysconfig/%{name}-gateway
cat > %{buildroot}%{_sysconfdir}/sysconfig/%{name}-gateway << 'EOF'
# OpenShell Gateway configuration
# See: openshell-gateway --help for all available options.

# ---- Required settings ----

# Shared secret for gateway-to-sandbox SSH handshake authentication.
# REQUIRED: Generate a value before starting the service:
#   openssl rand -hex 32
# The same secret must be shared with every sandbox that connects to
# this gateway.
OPENSHELL_SSH_HANDSHAKE_SECRET=

# Database URL for gateway state persistence.
# For the system unit this defaults to /var/lib/openshell/gateway.db.
# The user unit overrides this to ~/.local/state/openshell/gateway.db.
OPENSHELL_DB_URL=sqlite:///var/lib/openshell/gateway.db

# ---- Optional settings ----

# Compute driver: use Podman for sandbox container lifecycle.
OPENSHELL_DRIVERS=podman

# Supervisor image mounted into sandbox containers.
OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:latest

# Default sandbox base image.
OPENSHELL_SANDBOX_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest

# ---- SECURITY WARNING ----
# TLS is disabled by default for ease of initial setup. With TLS
# disabled, the gateway has NO authentication and listens on ALL
# network interfaces (0.0.0.0:8080). Any host that can reach this
# port has full unauthenticated access to the API, including sandbox
# creation, command execution, and credential retrieval.
#
# For any deployment beyond single-user localhost testing:
#   1. Generate mTLS certificates (see OpenShell docs)
#   2. Set OPENSHELL_TLS_CERT, OPENSHELL_TLS_KEY, OPENSHELL_TLS_CLIENT_CA
#   3. Comment out OPENSHELL_DISABLE_TLS below
OPENSHELL_DISABLE_TLS=true
EOF

# --- Gateway state directory ---
install -d %{buildroot}%{_sharedstatedir}/%{name}

# --- Python SDK ---
# Install Python SDK modules (test files are intentionally excluded)
install -d %{buildroot}%{python3_sitelib}/%{name}
install -d %{buildroot}%{python3_sitelib}/%{name}/_proto

install -pm 0644 python/%{name}/__init__.py %{buildroot}%{python3_sitelib}/%{name}/
install -pm 0644 python/%{name}/sandbox.py %{buildroot}%{python3_sitelib}/%{name}/
install -pm 0644 python/%{name}/_proto/__init__.py %{buildroot}%{python3_sitelib}/%{name}/_proto/
install -pm 0644 python/%{name}/_proto/*.py %{buildroot}%{python3_sitelib}/%{name}/_proto/

# Create dist-info so importlib.metadata can resolve the package version
install -d %{buildroot}%{python3_sitelib}/%{name}-%{version}.dist-info
cat > %{buildroot}%{python3_sitelib}/%{name}-%{version}.dist-info/METADATA << EOF
Metadata-Version: 2.1
Name: %{name}
Version: 0.0.37
Summary: OpenShell Python SDK for agent execution and management
License: Apache-2.0
Requires-Python: >=3.12
Requires-Dist: cloudpickle>=3.0
Requires-Dist: grpcio>=1.60
Requires-Dist: protobuf>=4.25
EOF

# INSTALLER marker per PEP 376
echo "rpm" > %{buildroot}%{python3_sitelib}/%{name}-%{version}.dist-info/INSTALLER

# RECORD can be empty for RPM-managed installs
touch %{buildroot}%{python3_sitelib}/%{name}-%{version}.dist-info/RECORD

%check
# Smoke-test the CLI binary
%{buildroot}%{_bindir}/%{name} --version

# Smoke-test the gateway binary
%{buildroot}%{_bindir}/%{name}-gateway --version

# Smoke-test the Python SDK version metadata via importlib.metadata.
# We query the dist-info directly rather than importing the package because
# the full import pulls in grpcio and other runtime deps not present in the
# build environment.
PYTHONPATH=%{buildroot}%{python3_sitelib} %{python3} -c "from importlib.metadata import version; v = version('openshell'); print(v); assert v == '%{version}', f'expected %{version}, got {v}'"

%post gateway
# Generate SSH handshake secret on fresh install if not already set.
# Uses /dev/urandom to avoid requiring openssl at install time.
SYSCONFIG=%{_sysconfdir}/sysconfig/%{name}-gateway
if [ -f "$SYSCONFIG" ] && grep -q '^OPENSHELL_SSH_HANDSHAKE_SECRET=$' "$SYSCONFIG" 2>/dev/null; then
    SECRET=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    sed -i "s/^OPENSHELL_SSH_HANDSHAKE_SECRET=$/OPENSHELL_SSH_HANDSHAKE_SECRET=${SECRET}/" "$SYSCONFIG"
fi
%systemd_post %{name}-gateway.service
%systemd_user_post %{name}-gateway.service

%preun gateway
%systemd_preun %{name}-gateway.service
%systemd_user_preun %{name}-gateway.service

%postun gateway
%systemd_postun_with_restart %{name}-gateway.service
%systemd_user_postun_with_restart %{name}-gateway.service

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}

%files gateway
%license LICENSE
%{_bindir}/%{name}-gateway
%{_unitdir}/%{name}-gateway.service
%{_userunitdir}/%{name}-gateway.service
%attr(0640,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/%{name}-gateway
%dir %{_sharedstatedir}/%{name}

%files -n python3-%{name}
%license LICENSE
%{python3_sitelib}/%{name}/
%{python3_sitelib}/%{name}-%{version}.dist-info/

%changelog
%autochangelog
