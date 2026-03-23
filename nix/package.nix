# OpenShell workspace build — produces openshell, openshell-server, openshell-sandbox.
{
  lib,
  rustPlatform,
  cmake,
  pkg-config,
  constants,
  sources,
}:

rustPlatform.buildRustPackage {
  pname = "openshell";
  version = constants.openshellVersion;
  src = sources.projectSrc;

  cargoLock.lockFile = sources.projectSrc + "/Cargo.lock";

  nativeBuildInputs = [
    cmake
    pkg-config
  ];

  cargoBuildFlags = [ "--workspace" ];

  # Tests require network access and a running cluster
  doCheck = false;

  postInstall = ''
    # Verify all expected binaries were built
    for bin in openshell openshell-server openshell-sandbox; do
      test -x "$out/bin/$bin" || (echo "ERROR: $bin not found in $out/bin" && exit 1)
    done
  '';

  meta = {
    description = "OpenShell — safe, sandboxed runtimes for autonomous AI agents";
    homepage = "https://github.com/NVIDIA/OpenShell";
    license = lib.licenses.asl20;
    mainProgram = "openshell";
  };
}
