# Shared configuration for all OpenShell Nix modules.
# Pure data — no nixpkgs dependency.
{
  openshellVersion = "0.0.0";

  # Container user (non-root)
  user = {
    name = "openshell";
    group = "openshell";
    uid = 65532;
    gid = 65532;
    home = "/home/openshell";
    shell = "/bin/bash";
  };

  # Patterns excluded from the project source derivation (projectSrc).
  # Only build artifacts and non-Rust files that don't affect the build.
  excludePatterns = [
    ".git"
    "target"
    "node_modules"
    "__pycache__"
    "nix"
    "python"
    "deploy"
    "docs"
    "e2e"
    ".agents"
    "architecture"
    ".github"
    ".vscode"
    "result"
  ];
}
