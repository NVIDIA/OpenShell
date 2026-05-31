# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

default_sandbox_image=ghcr.io/nvidia/openshell-community/sandboxes/base:latest

define install_and_setup_docker
- addgroup --system docker
- snap install docker
- while [ ! -S /run/docker.sock ]; do sleep 3; done
- "snap run docker pull $(default_sandbox_image)"
endef

define UBUNTU_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- snap wait system seed.loaded
$(install_and_setup_docker)
endef

define DEBIAN_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- systemctl enable --now snapd.socket snapd.service snapd.apparmor.service
- snap wait system seed.loaded
$(install_and_setup_docker)
packages:
- snapd
endef

define FEDORA_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- dnf install -y snapd
- systemctl enable --now snapd.socket
- snap wait system seed.loaded
- sudo ln -s /var/lib/snapd/snap /snap
$(install_and_setup_docker)
endef

define CENTOS_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
- yum install -y epel-release
- yum install -y snapd
- systemctl enable --now snapd.socket snapd.service
- snap wait system seed.loaded
- sudo ln -s /var/lib/snapd/snap /snap
$(install_and_setup_docker)
endef
