#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Image transport for the host launcher. The caller supplies fail/log/require_cmd
# and selects the gateway; no locality inference is made from its endpoint.
prepare_agent_image_transport() {
    local gateway_info
    gateway_info="$("$OPENSHELL_BIN" --gateway "$GATEWAY" gateway info --output json)" || fail "failed to inspect gateway '$GATEWAY'"
    GATEWAY_DRIVER="$(printf '%s' "$gateway_info" | ruby -rjson -e '
      drivers = JSON.parse(STDIN.read).fetch("compute_drivers", []).map { |d| d.fetch("name").downcase }
      abort "gateway must report exactly one compute driver" unless drivers.length == 1
      puts drivers.first
    ')" || fail "gateway '$GATEWAY' did not report exactly one compute driver"
    case "$GATEWAY_DRIVER" in
        docker|podman|kubernetes) ;;
        *) fail "unsupported agent compute driver: $GATEWAY_DRIVER" ;;
    esac

    if [[ -n "$AGENT_IMAGE" ]]; then
        [[ "$AGENT_IMAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$ ]] || fail "--image requires a digest-pinned image reference"
        [[ -z "$K3D_CLUSTER$PUBLISH_IMAGE" ]] || fail "--image cannot be combined with --k3d-cluster or --publish-image"
        IMAGE_MODE=prebuilt
        return
    fi

    if [[ -n "$K3D_CLUSTER" ]]; then
        [[ -z "$PUBLISH_IMAGE" ]] || fail "--k3d-cluster and --publish-image are mutually exclusive"
        [[ "$GATEWAY_DRIVER" == kubernetes ]] || fail "--k3d-cluster requires a Kubernetes gateway"
        [[ "$K3D_CLUSTER" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || fail "invalid k3d cluster name"
        require_cmd k3d
        require_cmd kubectl
        local context
        context="$(kubectl config current-context)" || fail "cannot determine Kubernetes context"
        [[ "$context" == "k3d-$K3D_CLUSTER" ]] || fail "selected kube context '$context' does not match k3d cluster '$K3D_CLUSTER'"
        k3d cluster list -o json | ruby -rjson -e '
          cluster = JSON.parse(STDIN.read).find { |c| c.fetch("name") == ARGV.fetch(0) }
          abort "selected local k3d cluster is not running" unless cluster && cluster.fetch("serversRunning", 0) > 0
        ' "$K3D_CLUSTER" || fail "cannot use local k3d cluster '$K3D_CLUSTER'"
        IMAGE_MODE=k3d
        set_agent_build_engine docker
    elif [[ -n "$PUBLISH_IMAGE" ]]; then
        # Require an explicit registry and tag. No implicit Docker Hub uploads.
        [[ "$PUBLISH_IMAGE" =~ ^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || fail "--publish-image requires REGISTRY/REPOSITORY:TAG"
        local registry="${PUBLISH_IMAGE%%/*}"
        [[ "$registry" == localhost || "$registry" == *.* || "$registry" == *:* ]] || fail "--publish-image requires an explicit registry hostname (use docker.io for Docker Hub)"
        IMAGE_MODE=registry
        if [[ "$GATEWAY_DRIVER" == kubernetes ]]; then
            # Registry builds may use either local engine, independently of the
            # engine used to host the remote Kubernetes cluster.
            source "$ROOT_DIR/tasks/scripts/container-engine.sh"
        else
            set_agent_build_engine "$GATEWAY_DRIVER"
        fi
    elif [[ "$GATEWAY_DRIVER" == kubernetes ]]; then
        fail "Kubernetes needs --image REGISTRY/REPOSITORY@sha256:DIGEST, --k3d-cluster NAME, or --publish-image REGISTRY/REPOSITORY:TAG"
    else
        IMAGE_MODE=engine
        set_agent_build_engine "$GATEWAY_DRIVER"
    fi
}

set_agent_build_engine() {
    local engine="$1"
    if [[ -n "${CONTAINER_ENGINE:-}" && "$(printf '%s' "$CONTAINER_ENGINE" | tr '[:upper:]' '[:lower:]')" != "$engine" ]]; then
        fail "CONTAINER_ENGINE=$CONTAINER_ENGINE conflicts with required image build engine '$engine'"
    fi
    CONTAINER_ENGINE="$engine"
    export CONTAINER_ENGINE
    source "$ROOT_DIR/tasks/scripts/container-engine.sh"
}

deliver_agent_image() {
    local image_tag="$1"
    case "$IMAGE_MODE" in
        k3d)
            log "Importing '$image_tag' into k3d cluster '$K3D_CLUSTER'."
            k3d image import --cluster "$K3D_CLUSTER" "$image_tag" || fail "k3d image import failed"
            SANDBOX_FROM="$image_tag"
            ;;
        registry)
            log "Publishing '$image_tag'."
            ce push "$image_tag" || fail "image push failed"
            local repository="${image_tag%:*}"
            SANDBOX_FROM="$(ce image inspect "$image_tag" --format '{{json .RepoDigests}}' | ruby -rjson -e '
              digests = JSON.parse(STDIN.read) || []
              normalize = lambda do |repository|
                # Docker omits its default registry in RepoDigests.
                repository = repository.sub(/\A(?:docker\.io|index\.docker\.io)\//, "")
                repository.include?("/") ? repository : "library/#{repository}"
              end
              digest = digests.find { |d| normalize.call(d.split("@", 2).first) == normalize.call(ARGV.fetch(0)) && d.match?(/@sha256:[a-f0-9]{64}\z/) }
              abort "push did not produce a matching repository digest" unless digest
              puts "#{ARGV.fetch(0)}@#{digest.split("@", 2).last}"
            ' "$repository")" || fail "cannot resolve published image digest; refusing mutable-tag launch"
            ;;
        engine) SANDBOX_FROM="$image_tag" ;;
        *) fail "invalid image delivery mode: $IMAGE_MODE" ;;
    esac
}
