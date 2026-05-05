# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

%global crate openshell

# Cargo/Rust builds with vendored deps do not produce debugsource listings
# in the format redhat-rpm-config expects (especially on EPEL).
%global debug_package %{nil}

Name:           openshell
Version:        0.0.37
Release:        1.20260505111703438211.rpm.100.gec0e2ce3%{?dist}
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
BuildRequires:  cargo-rpm-macros >= 25
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  cmake
BuildRequires:  pkg-config
BuildRequires:  clang-devel
BuildRequires:  z3-devel
BuildRequires:  systemd-rpm-macros

# Man page generation
BuildRequires:  pandoc

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
Requires:       openssl
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

# Extract vendored Cargo dependencies and configure offline build
tar xf %{SOURCE1}
%cargo_prep -v vendor

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

# Generate vendored crate manifest and license metadata.
# cargo-vendor.txt is consumed by an RPM generator (from cargo-rpm-macros)
# to emit Provides: bundled(crate(...)) = version for every vendored dep.
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

# Build man pages from markdown
pandoc -s -t man deploy/man/openshell.1.md -o openshell.1
pandoc -s -t man deploy/man/openshell-gateway.8.md -o openshell-gateway.8
pandoc -s -t man deploy/man/openshell-gateway.env.5.md -o openshell-gateway.env.5

%install
# --- CLI binary ---
install -Dpm 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# --- Gateway binary ---
install -Dpm 0755 target/release/%{name}-gateway %{buildroot}%{_bindir}/%{name}-gateway

# --- Gateway systemd user unit (rootless Podman) ---
# Installed to the systemd user unit directory so any user can run:
#   systemctl --user enable --now openshell-gateway.service
# Podman socket activation provides the container API.
install -d %{buildroot}%{_userunitdir}
cat > %{buildroot}%{_userunitdir}/%{name}-gateway.service << 'EOF'
[Unit]
Description=OpenShell Gateway (user)
Documentation=https://github.com/NVIDIA/OpenShell
After=podman.socket
Requires=podman.socket

[Service]
Type=exec
# Self-contained defaults for rootless operation with mTLS.
#
# PKI and gateway.env are auto-generated on first start. Client certs
# are placed in ~/.config/openshell/gateways/openshell/mtls/ so the
# CLI discovers them automatically.
# See /usr/share/doc/openshell-gateway/ for details.

# Auto-generate PKI on first start if not present.
# %%S expands to $XDG_STATE_HOME (~/.local/state) in user units.
ExecStartPre=%{_libexecdir}/openshell/init-pki.sh %%S/openshell/tls

# Auto-generate gateway.env (SSH handshake secret + commented config
# reference) on first start if not present.
# %%E expands to $XDG_CONFIG_HOME (~/.config) in user units.
ExecStartPre=%{_libexecdir}/openshell/init-gateway-env.sh %%E/openshell/gateway.env
EnvironmentFile=-%%E/openshell/gateway.env
Environment=OPENSHELL_BIND_ADDRESS=0.0.0.0
Environment=OPENSHELL_DRIVERS=podman
Environment=OPENSHELL_DB_URL=sqlite://%%S/openshell/gateway.db
Environment=OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:latest
Environment=OPENSHELL_SANDBOX_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest
# mTLS: auto-generated certs in the state directory.
Environment=OPENSHELL_TLS_CERT=%%S/openshell/tls/server/tls.crt
Environment=OPENSHELL_TLS_KEY=%%S/openshell/tls/server/tls.key
Environment=OPENSHELL_TLS_CLIENT_CA=%%S/openshell/tls/ca.crt
# Podman driver: client certs bind-mounted into sandbox containers.
Environment=OPENSHELL_PODMAN_TLS_CA=%%S/openshell/tls/ca.crt
Environment=OPENSHELL_PODMAN_TLS_CERT=%%S/openshell/tls/client/tls.crt
Environment=OPENSHELL_PODMAN_TLS_KEY=%%S/openshell/tls/client/tls.key
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

# --- PKI bootstrap script and gateway env generator ---
install -d %{buildroot}%{_libexecdir}/%{name}
install -pm 0755 deploy/rpm/init-pki.sh %{buildroot}%{_libexecdir}/%{name}/init-pki.sh
install -pm 0755 deploy/rpm/init-gateway-env.sh %{buildroot}%{_libexecdir}/%{name}/init-gateway-env.sh

# --- Gateway documentation ---
install -d %{buildroot}%{_docdir}/%{name}-gateway
install -pm 0644 deploy/rpm/QUICKSTART.md %{buildroot}%{_docdir}/%{name}-gateway/QUICKSTART.md
install -pm 0644 deploy/rpm/CONFIGURATION.md %{buildroot}%{_docdir}/%{name}-gateway/CONFIGURATION.md
install -pm 0644 deploy/rpm/TROUBLESHOOTING.md %{buildroot}%{_docdir}/%{name}-gateway/TROUBLESHOOTING.md

# --- Man pages ---
install -Dpm 0644 openshell.1 %{buildroot}%{_mandir}/man1/openshell.1
install -Dpm 0644 openshell-gateway.8 %{buildroot}%{_mandir}/man8/openshell-gateway.8
install -Dpm 0644 openshell-gateway.env.5 %{buildroot}%{_mandir}/man5/openshell-gateway.env.5

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
%systemd_user_post %{name}-gateway.service

%preun gateway
%systemd_user_preun %{name}-gateway.service

%postun gateway
%systemd_user_postun_with_restart %{name}-gateway.service

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%doc README.md
%{_bindir}/%{name}
%{_mandir}/man1/openshell.1*

%files gateway
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%doc %{_docdir}/%{name}-gateway/QUICKSTART.md
%doc %{_docdir}/%{name}-gateway/CONFIGURATION.md
%doc %{_docdir}/%{name}-gateway/TROUBLESHOOTING.md
%{_bindir}/%{name}-gateway
%{_userunitdir}/%{name}-gateway.service
%{_libexecdir}/%{name}/init-pki.sh
%{_libexecdir}/%{name}/init-gateway-env.sh
%{_mandir}/man8/openshell-gateway.8*
%{_mandir}/man5/openshell-gateway.env.5*

%files -n python3-%{name}
%license LICENSE
%{python3_sitelib}/%{name}/
%{python3_sitelib}/%{name}-%{version}.dist-info/

%changelog
%autochangelog
