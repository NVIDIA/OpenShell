#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

echo "==> Installing OpenShell development dependencies on CentOS Stream"
sudo dnf install -y \
	ca-certificates \
	clang \
	clang-devel \
	cmake \
	curl \
	gcc \
	gcc-c++ \
	git \
	jq \
	make \
	openssh-clients \
	openssl-devel \
	pkgconf-pkg-config \
	python3 \
	rsync \
	socat \
	unzip \
	xz \
	zstd

z3_version="4.16.0"
case "$(uname -m)" in
	aarch64)
		z3_asset="z3-${z3_version}-arm64-glibc-2.38.zip"
		z3_sha256="87fcd963d3eecb0f12cf1c3ef0ad74e84a3a7bd3caed5d94445645ef94ae6274"
		;;
	x86_64)
		z3_asset="z3-${z3_version}-x64-glibc-2.39.zip"
		z3_sha256="7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e"
		;;
	*)
		echo "unsupported architecture for Z3: $(uname -m)" >&2
		exit 1
		;;
esac

if pkg-config --atleast-version="${z3_version}" z3 2>/dev/null; then
	echo "==> Z3 $(pkg-config --modversion z3) is already installed"
else
	echo "==> Installing Z3 ${z3_version} for OpenShell development"
	work_dir="$(mktemp -d)"
	trap 'rm -rf "${work_dir}"' EXIT
	archive="${work_dir}/${z3_asset}"
	curl -fL \
		"https://github.com/Z3Prover/z3/releases/download/z3-${z3_version}/${z3_asset}" \
		-o "${archive}"
	printf '%s  %s\n' "${z3_sha256}" "${archive}" | sha256sum --check --status
	unzip -q "${archive}" -d "${work_dir}"
	z3_dir="${work_dir}/${z3_asset%.zip}"

	sudo install -D -m 0755 "${z3_dir}/bin/z3" /usr/local/bin/z3
	sudo install -D -m 0755 "${z3_dir}/bin/libz3.so" /usr/local/lib/libz3.so
	sudo install -d -m 0755 /usr/local/include
	sudo install -m 0644 "${z3_dir}"/include/*.h /usr/local/include/
	sudo install -d -m 0755 /usr/lib64/pkgconfig
	sudo tee /usr/lib64/pkgconfig/z3.pc >/dev/null <<EOF
prefix=/usr/local
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: z3
Description: The Z3 theorem prover
Version: ${z3_version}
Libs: -L\${libdir} -lz3
Cflags: -I\${includedir}
EOF
	echo /usr/local/lib | sudo tee /etc/ld.so.conf.d/z3.conf >/dev/null
	sudo ldconfig

	test "$(pkg-config --modversion z3)" = "${z3_version}"
	z3 --version
	rm -rf "${work_dir}"
	trap - EXIT
fi
