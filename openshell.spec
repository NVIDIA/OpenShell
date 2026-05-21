# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

%global crate openshell
%global openshell_version 0.0.37
%global openshell_cargo_version %{openshell_version}
# Python dist-info metadata intentionally follows the RPM Version. Dev build
# identity is represented by Release for RPM packages.
%global openshell_python_version %{openshell_version}

# Cargo/Rust builds with vendored deps do not produce debugsource listings
# in the format redhat-rpm-config expects (especially on EPEL).
%global debug_package %{nil}

# Default container image tag for supervisor and sandbox images.
# Overridden to 'latest' by Packit's fix-spec-file action for tagged stable
# releases (via git describe --exact-match). PR and commit-to-main builds
# keep the default 'dev' so they track the development image stream.
%global image_tag dev

Name:           openshell
Version:        %{openshell_version}
Release:        1.20260518180028805757.podman.toml.gateway.listener.11.g8c0cb7c8%{?dist}
Summary:        Safe, sandboxed runtimes for autonomous AI agents

License:        Apache-2.0
URL:            https://github.com/NVIDIA/OpenShell
Source0: openshell-%{openshell_version}.tar.gz
Source1: openshell-%{openshell_version}-vendor.tar.xz

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

# Runtime: container runtime for package-managed gateway sandboxes.
# The gateway auto-detects Podman when the package-managed service starts.
Recommends:     podman

%description
OpenShell provides safe, sandboxed runtimes for autonomous AI agents.
It offers a CLI for managing gateway registrations, sandboxes, and providers with
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
lifecycle management. This package installs Podman-oriented defaults in
gateway TOML while leaving compute driver selection to gateway auto-detection
or explicit operator configuration.

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

# Patch workspace version from placeholder to actual build identity.
sed -i 's/^version = "0.0.0"/version = "%{openshell_cargo_version}"/' Cargo.toml
grep -q 'version = "%{openshell_cargo_version}"' Cargo.toml || (echo "ERROR: Cargo.toml version patch failed" && exit 1)

%build
# Build the CLI and gateway binaries
export CARGO_BUILD_JOBS=%{_smp_build_ncpus}
# Set the default container image tag so compiled-in image refs point at
# real tags in the ghcr.io/nvidia/openshell registry.
export OPENSHELL_IMAGE_TAG=%{image_tag}
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

%install
# --- CLI binary ---
install -Dpm 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# --- Gateway binary ---
install -Dpm 0755 target/release/%{name}-gateway %{buildroot}%{_bindir}/%{name}-gateway

# --- Default gateway TOML config template ---
# Shipped as a read-only reference in %{_datadir}. The systemd unit seeds a
# user-level copy at ~/.config/openshell/gateway.toml on first start.
install -Dpm 0644 deploy/rpm/gateway.toml.default %{buildroot}%{_datadir}/%{name}-gateway/gateway.toml.default

# --- Gateway systemd user unit ---
# Installed to the systemd user unit directory so any user can run:
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
# On first start the unit seeds a default TOML config and generates PKI.
# Client certs are placed in ~/.config/openshell/gateways/openshell/mtls/ so
# the CLI discovers them automatically.
# See /usr/share/doc/openshell-gateway/ for details.

# Seed a default TOML config on first start if the user has not created one.
# The template ships at /usr/share/openshell-gateway/gateway.toml.default.
# Edit ~/.config/openshell/gateway.toml to customize.
# %%E expands to $XDG_CONFIG_HOME (~/.config) in user units.
ExecStartPre=/bin/sh -c 'test -f %%E/openshell/gateway.toml || install -Dm644 /usr/share/openshell-gateway/gateway.toml.default %%E/openshell/gateway.toml'

# Auto-generate PKI on first start if not present.
# %%S expands to $XDG_STATE_HOME (~/.local/state) in user units.
ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir %%S/openshell/tls --server-san host.openshell.internal

# gateway.env is honored for backward compatibility with pre-1415 installs.
# New installs use runtime defaults; create gateway.toml to override.
# See TROUBLESHOOTING.md for the env-to-TOML migration guide.
EnvironmentFile=-%%E/openshell/gateway.env
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

# --- Gateway documentation ---
install -d %{buildroot}%{_docdir}/%{name}-gateway
install -pm 0644 deploy/rpm/QUICKSTART.md %{buildroot}%{_docdir}/%{name}-gateway/QUICKSTART.md
install -pm 0644 deploy/rpm/CONFIGURATION.md %{buildroot}%{_docdir}/%{name}-gateway/CONFIGURATION.md
install -pm 0644 deploy/rpm/TROUBLESHOOTING.md %{buildroot}%{_docdir}/%{name}-gateway/TROUBLESHOOTING.md

# --- Man pages ---
install -Dpm 0644 openshell.1 %{buildroot}%{_mandir}/man1/openshell.1
install -Dpm 0644 openshell-gateway.8 %{buildroot}%{_mandir}/man8/openshell-gateway.8

# --- Python SDK ---
# Install Python SDK modules (test files are intentionally excluded)
install -d %{buildroot}%{python3_sitelib}/%{name}
install -d %{buildroot}%{python3_sitelib}/%{name}/_proto

install -pm 0644 python/%{name}/__init__.py %{buildroot}%{python3_sitelib}/%{name}/
install -pm 0644 python/%{name}/sandbox.py %{buildroot}%{python3_sitelib}/%{name}/
install -pm 0644 python/%{name}/_proto/__init__.py %{buildroot}%{python3_sitelib}/%{name}/_proto/
install -pm 0644 python/%{name}/_proto/*.py %{buildroot}%{python3_sitelib}/%{name}/_proto/

# Create dist-info so importlib.metadata can resolve the package version
install -d %{buildroot}%{python3_sitelib}/%{name}-%{openshell_python_version}.dist-info
cat > %{buildroot}%{python3_sitelib}/%{name}-%{openshell_python_version}.dist-info/METADATA << EOF
Metadata-Version: 2.1
Name: %{name}
Version: %{openshell_python_version}
Summary: OpenShell Python SDK for agent execution and management
License: Apache-2.0
Requires-Python: >=3.12
Requires-Dist: cloudpickle>=3.0
Requires-Dist: grpcio>=1.60
Requires-Dist: protobuf>=4.25
EOF

# INSTALLER marker per PEP 376
echo "rpm" > %{buildroot}%{python3_sitelib}/%{name}-%{openshell_python_version}.dist-info/INSTALLER

# RECORD can be empty for RPM-managed installs
touch %{buildroot}%{python3_sitelib}/%{name}-%{openshell_python_version}.dist-info/RECORD

%check
# Smoke-test the CLI binary
%{buildroot}%{_bindir}/%{name} --version

# Smoke-test the gateway binary
%{buildroot}%{_bindir}/%{name}-gateway --version

# Smoke-test the Python SDK version metadata via importlib.metadata.
# We query the dist-info directly rather than importing the package because
# the full import pulls in grpcio and other runtime deps not present in the
# build environment.
PYTHONPATH=%{buildroot}%{python3_sitelib} %{python3} -c "from importlib.metadata import version; v = version('openshell'); print(v); assert v == '%{openshell_python_version}', f'expected %{openshell_python_version}, got {v}'"

# Verify the RPM default TOML config template was installed.
# A missing template means first-start seeding silently falls back to the
# binary default of 127.0.0.1, which breaks Podman sandbox connectivity.
test -f %{buildroot}%{_datadir}/%{name}-gateway/gateway.toml.default

# Verify the systemd unit references the template in its ExecStartPre seed step.
# If this grep fails, the first-start seeding logic was removed from the unit.
grep -q 'gateway.toml.default' %{buildroot}%{_userunitdir}/%{name}-gateway.service

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
%{_datadir}/%{name}-gateway/gateway.toml.default
%{_mandir}/man8/openshell-gateway.8*

%files -n python3-%{name}
%license LICENSE
%{python3_sitelib}/%{name}/
%{python3_sitelib}/%{name}-%{openshell_python_version}.dist-info/

%changelog
%autochangelog
