# OCI container image via dockerTools.buildLayeredImage.
# Minimal image: Rust binaries + bash + coreutils + CA certs.
{
  lib,
  dockerTools,
  writeTextFile,
  bash,
  coreutils,
  cacert,
  constants,
  openshell,
}:

let
  # Generate /etc/passwd and /etc/group entries
  passwdEntry = ''
    root:x:0:0:root:/root:/bin/bash
    ${constants.user.name}:x:${toString constants.user.uid}:${toString constants.user.gid}:${constants.user.name}:${constants.user.home}:${constants.user.shell}
  '';

  groupEntry = ''
    root:x:0:
    ${constants.user.group}:x:${toString constants.user.gid}:
  '';

  passwd = writeTextFile {
    name = "passwd";
    text = passwdEntry;
  };
  group = writeTextFile {
    name = "group";
    text = groupEntry;
  };

in
dockerTools.buildLayeredImage {
  name = "openshell";
  tag = constants.openshellVersion;
  maxLayers = 80;

  contents = [
    bash
    coreutils
    cacert
    openshell
  ];

  fakeRootCommands = ''
    # /etc entries
    mkdir -p ./etc
    cp ${passwd} ./etc/passwd
    cp ${group}  ./etc/group

    # Home directory for non-root user
    mkdir -p .${constants.user.home}
    chown -R ${toString constants.user.uid}:${toString constants.user.gid} .${constants.user.home}
  '';

  config = {
    Entrypoint = [
      "${openshell}/bin/openshell"
      "--help"
    ];
    Cmd = [ ];
    User = "${toString constants.user.uid}:${toString constants.user.gid}";
    WorkingDir = constants.user.home;
    Env = [
      "PATH=/usr/local/bin:/usr/bin:/bin:${lib.makeBinPath [ openshell ]}"
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
  };
}
