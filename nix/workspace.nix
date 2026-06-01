# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Crate-by-crate crane helpers for a Cargo workspace.
#
# Each crate is built from a minimal source, its own code plus that of its
# transitive workspace dependencies, and gets its own dependency cache. Crates
# outside that closure are reduced to their Cargo.toml so cargo can resolve
# the workspace without their source and without any Cargo.toml edits.
# Editing one crate never rebuilds an unrelated crate, and (because crane
# launders the source before building deps) never rebuilds any crate's
# dependency cache.
{
  lib,
  pkgs,
  craneLib,
  # Workspace root: holds the virtual Cargo.toml, Cargo.lock and .cargo/.
  root,
  # Member directory, relative to root.
  crateDir ? "crates",
  # Version stamped onto every crate derivation.
  version ? "0.0.0",
}:
let
  cratesRoot = root + "/${crateDir}";

  # Workspace dependency graph, derived from the Cargo.tomls
  crateDirs = lib.attrNames (lib.filterAttrs (_: t: t == "directory") (builtins.readDir cratesRoot));

  # Direct intra-workspace path-dependencies of a crate, as dir names.
  directDeps =
    dir:
    let
      manifest = builtins.fromTOML (builtins.readFile (cratesRoot + "/${dir}/Cargo.toml"));
    in
    lib.pipe (manifest.dependencies or { }) [
      lib.attrValues
      (lib.filter (v: builtins.isAttrs v && v ? path))
      (map (v: baseNameOf v.path))
      (lib.filter (d: builtins.elem d crateDirs))
    ];

  # Transitive closure of a crate within the workspace: its own dir plus every workspace dep.
  closureOf =
    dir:
    map (e: e.key) (
      builtins.genericClosure {
        startSet = [ { key = dir; } ];
        operator = e: map (key: { inherit key; }) (directDeps e.key);
      }
    );

  # Every member's Cargo.toml, cargo must see all of them to resolve the
  # workspace even for crates whose source we leave out.
  allManifests = map (d: cratesRoot + "/${d}/Cargo.toml") crateDirs;

  # Source tree carrying the real sources of the given crate dirs, plus every
  # member's Cargo.toml and the given assets.
  mkSrc =
    {
      dirs,
      assets ? [ ],
    }:
    lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions (
        [
          (root + "/Cargo.toml")
          (root + "/Cargo.lock")
          (root + "/.cargo")
        ]
        ++ allManifests
        ++ map (d: craneLib.fileset.commonCargoSources (cratesRoot + "/${d}")) dirs
        ++ assets
      );
    };

  # Build one workspace crate (pname == dir) in three cached layers. Every layer
  # uses the SAME `-p <dir>` selection, so cargo's feature unification is
  # identical across them and the compiled artifacts are reusable:
  #   1. crates.io deps      — buildDepsOnly; immune to first-party code.
  #   2. workspace-dep libs  — build `-p <dir>` with the crate's OWN source
  #                            stubbed (real path-deps), so its libs compile with
  #                            the crate's real feature set and get cached.
  #   3. the crate itself    — reuses 1 + 2; only the crate's own code recompiles.
  buildWorkspaceCrate =
    {
      dir,
      assets ? [ ],
      nativeBuildInputs ? [ ],
      buildInputs ? [ ],
      env ? { },
    }:
    let
      closure = closureOf dir;
      workspaceDeps = lib.filter (d: d != dir) closure;
      common = {
        pname = dir;
        inherit
          version
          nativeBuildInputs
          buildInputs
          env
          ;
        strictDeps = true;
        # Build only, skip the cargo test/check phase for now.
        doCheck = false;
        cargoExtraArgs = "--locked -p ${dir}";
      };

      cratesDeps = craneLib.buildDepsOnly (common // { src = mkSrc { dirs = [ ]; }; });

      mkWorkspaceLibsSrc =
        let
          base = mkSrc {
            dirs = workspaceDeps;
            inherit assets;
          };
          dummyCrate = craneLib.mkDummySrc { src = cratesRoot + "/${dir}"; };
        in
        pkgs.runCommandLocal "source" { } ''
          cp -r ${base} $out
          chmod -R u+w $out
          rm -rf "$out/${crateDir}/${dir}"
          cp -r ${dummyCrate} "$out/${crateDir}/${dir}"
        '';

      workspaceLibs =
        if workspaceDeps == [ ] then
          cratesDeps
        else
          craneLib.buildPackage (
            common
            // {
              pname = "${dir}-workspace-libs";
              src = mkWorkspaceLibsSrc;
              cargoArtifacts = cratesDeps;
              doInstallCargoArtifacts = true;
              postInstall = ''
                cargo clean --release -p ${dir}
              '';
            }
          );
    in
    craneLib.buildPackage (
      common
      // {
        src = mkSrc {
          dirs = closure;
          inherit assets;
        };
        cargoArtifacts = workspaceLibs;
      }
    );
in
{
  inherit buildWorkspaceCrate;
}
