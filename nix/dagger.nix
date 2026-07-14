{
  fetchurl,
  lib,
  stdenvNoCC,
  version,
}:

let
  sources = {
    aarch64-darwin = {
      platform = "darwin_arm64";
      hash = "sha256-uxRyzXHv5AuaXRkpROsLCV6PVWbhh50Whk8tYOednHc=";
    };
    aarch64-linux = {
      platform = "linux_arm64";
      hash = "sha256-eA6N3EJpru6U7yGrfLBsou4Eq+xUhuulP0mnVJ2ZY30=";
    };
    x86_64-linux = {
      platform = "linux_amd64";
      hash = "sha256-REMK/G+cOQ/EfE81KxXekwml6X69GuVjg5YX1t+OjMU=";
    };
  };
  source =
    sources.${stdenvNoCC.hostPlatform.system}
      or (throw "unsupported Dagger system: ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "dagger";
  inherit version;

  src = fetchurl {
    url = "https://github.com/dagger/dagger/releases/download/v${version}/dagger_v${version}_${source.platform}.tar.gz";
    inherit (source) hash;
  };

  sourceRoot = ".";
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 dagger "$out/bin/dagger"
    runHook postInstall
  '';

  meta = {
    description = "Application delivery engine for CI/CD";
    homepage = "https://dagger.io";
    license = lib.licenses.asl20;
    mainProgram = "dagger";
    platforms = builtins.attrNames sources;
  };
}
