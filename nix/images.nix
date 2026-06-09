# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  pkgs,
  gateway,
  supervisor,
}:
{
  openshell-gateway-image = pkgs.dockerTools.buildLayeredImage {
    name = "openshell/gateway";
    tag = "nix";

    contents = [
      gateway
      pkgs.cacert
    ];

    extraCommands = ''
      mkdir -p app usr/local/bin
      cp --dereference ${gateway}/bin/openshell-gateway usr/local/bin/openshell-gateway
      chmod 0555 usr/local/bin/openshell-gateway
    '';

    config = {
      Entrypoint = [ "/usr/local/bin/openshell-gateway" ];
      Cmd = [
        "--bind-address"
        "0.0.0.0"
        "--port"
        "8080"
      ];
      Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
      ExposedPorts = {
        "8080/tcp" = { };
      };
      User = "1000:1000";
      WorkingDir = "/app";
    };
  };

  openshell-supervisor-image = pkgs.dockerTools.buildLayeredImage {
    name = "openshell/supervisor";
    tag = "nix";

    contents = [ supervisor ];

    extraCommands = ''
      cp --dereference ${supervisor}/bin/openshell-sandbox openshell-sandbox
      chmod 0550 openshell-sandbox
    '';

    config = {
      Entrypoint = [ "/openshell-sandbox" ];
    };
  };
}
