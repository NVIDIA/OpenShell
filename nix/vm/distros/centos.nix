# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{ pkgs, architecture }:

{
  osId = "centos";
  osVersion = "10";
  packageFamily = "rpm";
  image = pkgs.fetchurl {
    name = "CentOS-Stream-GenericCloud-10-20260720.0.${architecture}.qcow2";
    url = "https://cloud.centos.org/centos/10-stream/${architecture}/images/CentOS-Stream-GenericCloud-10-20260720.0.${architecture}.qcow2";
    hash =
      if architecture == "aarch64" then
        "sha256-55IuyMUvsbpvqgug2S7w6JpLCSIpR4HJVkuMch60Rag="
      else
        "sha256-k3lpRd9eVJUr4hyoUGfwyfOxGi3W7iFjFU/ZdIxMQdc=";
  };
}
