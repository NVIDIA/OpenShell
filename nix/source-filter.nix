# Reusable source filtering for OpenShell builds.
# Keeps derivations from rebuilding when unrelated files change.
{ lib, constants }:

let
  root = ./..;

  # Filter that excludes patterns listed in constants.excludePatterns
  excludeFilter =
    path: _type:
    let
      baseName = baseNameOf (toString path);
    in
    !builtins.elem baseName constants.excludePatterns;

  # Full project source minus excluded directories
  projectSrc = lib.cleanSourceWith {
    src = root;
    filter = excludeFilter;
    name = "openshell-source";
  };

in
{
  inherit projectSrc;
}
