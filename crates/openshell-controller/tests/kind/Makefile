# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Out-of-cluster iteration loop for openshell-controller.
#
# Typical session:
#   make up                # create kind cluster + apply CRD
#   make standalone        # run reconciler against kind (foreground)
#   make sample            # in another shell: apply a sample OpenShellSandbox
#   make status            # see the CR + its observed status
#   make down              # delete the kind cluster

.PHONY: up down recreate standalone sample status logs

HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(HERE)../../../..)

up:
	@$(HERE)bootstrap.sh

down:
	@$(HERE)teardown.sh

recreate: down up

# Foreground run of the reconciler. Quit with Ctrl-C.
# Watches the `default` namespace by default; override via env var.
# bootstrap.sh writes the kind kubeconfig into $REPO_ROOT/kubeconfig, which
# mise.toml's `[env].KUBECONFIG` already points at — so `mise exec` picks
# it up without further plumbing.
standalone:
	@cd $(REPO_ROOT) && \
	 OPENSHELL_CONTROLLER_WATCH_NAMESPACE=$${OPENSHELL_CONTROLLER_WATCH_NAMESPACE:-default} \
	 OPENSHELL_CONTROLLER_LOG_FILTER=$${OPENSHELL_CONTROLLER_LOG_FILTER:-info,openshell_controller=debug,kube=warn} \
	 mise exec -- cargo run --example standalone -p openshell-controller

sample:
	@kubectl apply -f $(HERE)sample.yaml

status:
	@kubectl get oshs -A
	@echo
	@kubectl get oshs sample -o yaml | sed -n '/^status:/,$$p' || true

logs:
	@echo "standalone runs in foreground; logs appear on its terminal"
