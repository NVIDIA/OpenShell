# Dev shell with all build, lint, and test tools.
{
  mkShell,
  rustc,
  cargo,
  clippy,
  rustfmt,
  cmake,
  pkg-config,
  protobuf,
  git,
  curl,
  kubectl,
  kubernetes-helm,
  shellcheck,
  shfmt,
  hadolint,
  ruff,
  cargo-about,
  syft,
  openshell,
}:

mkShell {
  # Inherit build dependencies from the openshell package
  inputsFrom = [ openshell ];

  packages = [
    # Rust toolchain
    rustc
    cargo
    clippy
    rustfmt

    # Build tools
    cmake
    pkg-config
    protobuf

    # Core
    git
    curl

    # Kubernetes
    kubectl
    kubernetes-helm

    # Linters / formatters
    shellcheck
    shfmt
    hadolint
    ruff

    # Compliance
    cargo-about
    syft
  ];

  shellHook = ''
    echo "OpenShell dev shell"
    echo "  rustc:  $(rustc --version)"
    echo "  cargo:  $(cargo --version)"
    echo "  protoc: $(protoc --version)"
    echo ""
    echo "Quick start:"
    echo "  cargo build              — build workspace"
    echo "  cargo clippy             — lint"
    echo "  cargo test               — run tests"
    echo "  nix build                — reproducible build"
    echo "  nix build .#container    — build OCI container"
  '';
}
