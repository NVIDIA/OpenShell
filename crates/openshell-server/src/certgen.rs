// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `generate-certs` subcommand: bootstrap mTLS PKI for the gateway.
//!
//! Two output modes, dispatched by the presence of `--output-dir`:
//!
//! - **Kubernetes mode** (default): create two `kubernetes.io/tls` Secrets
//!   in the supplied namespace. Used by the Helm pre-install hook. Requires
//!   `--namespace`, `--server-secret-name`, `--client-secret-name`.
//! - **Local mode** (`--output-dir <DIR>`): write PEMs to a filesystem layout
//!   matching `deploy/rpm/init-pki.sh`. Used by the RPM systemd unit's
//!   `ExecStartPre`. Also copies client materials to
//!   `$XDG_CONFIG_HOME/openshell/gateways/openshell/mtls/` so the local CLI
//!   picks them up automatically.
//!
//! Both modes share the same idempotency contract: all targets present →
//! skip; partial state → error with a recovery hint; nothing present →
//! generate and write.

use clap::Args;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_bootstrap::pki::{PkiBundle, generate_pki};
use openshell_core::paths::{create_dir_restricted, set_file_owner_only};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Args, Debug)]
pub struct CertgenArgs {
    /// Write PEMs to a filesystem directory instead of Kubernetes Secrets.
    /// When set, the kube-related flags are not required.
    #[arg(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// Kubernetes namespace to create Secrets in.
    /// Default comes from `POD_NAMESPACE`, which the Helm hook injects via
    /// the downward API.
    #[arg(long, env = "POD_NAMESPACE", required_unless_present = "output_dir")]
    namespace: Option<String>,

    /// Name of the server TLS Secret (`kubernetes.io/tls`) to create.
    #[arg(long, required_unless_present = "output_dir")]
    server_secret_name: Option<String>,

    /// Name of the client TLS Secret (`kubernetes.io/tls`) to create.
    #[arg(long, required_unless_present = "output_dir")]
    client_secret_name: Option<String>,

    /// Extra Subject Alternative Name for the server certificate. Repeatable.
    /// Auto-detected as an IP address or DNS name.
    #[arg(long = "server-san", value_name = "SAN")]
    server_sans: Vec<String>,

    /// Print the generated PEM materials to stdout instead of writing them.
    /// For local debugging.
    #[arg(long)]
    dry_run: bool,
}

pub async fn run(args: CertgenArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if args.dry_run {
        let bundle = generate_pki(&args.server_sans)?;
        print_bundle(&bundle);
        return Ok(());
    }

    if let Some(dir) = args.output_dir.as_deref() {
        run_local(dir, &args.server_sans)
    } else {
        let bundle = generate_pki(&args.server_sans)?;
        run_kubernetes(&args, &bundle).await
    }
}

// ─────────────────────────── Kubernetes mode ───────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum K8sAction {
    SkipExists,
    PartialState,
    Create,
}

fn decide_k8s(server_exists: bool, client_exists: bool) -> K8sAction {
    match (server_exists, client_exists) {
        (true, true) => K8sAction::SkipExists,
        (false, false) => K8sAction::Create,
        _ => K8sAction::PartialState,
    }
}

async fn run_kubernetes(args: &CertgenArgs, bundle: &PkiBundle) -> Result<()> {
    let namespace = args
        .namespace
        .as_deref()
        .ok_or_else(|| miette::miette!("--namespace is required (or set POD_NAMESPACE)"))?;
    let server_name = args
        .server_secret_name
        .as_deref()
        .ok_or_else(|| miette::miette!("--server-secret-name is required"))?;
    let client_name = args
        .client_secret_name
        .as_deref()
        .ok_or_else(|| miette::miette!("--client-secret-name is required"))?;

    let client = Client::try_default()
        .await
        .into_diagnostic()
        .wrap_err("failed to construct in-cluster Kubernetes client")?;
    let api: Api<Secret> = Api::namespaced(client, namespace);

    let server_exists = api
        .get_opt(server_name)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read secret {server_name}"))?
        .is_some();
    let client_exists = api
        .get_opt(client_name)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read secret {client_name}"))?
        .is_some();

    match decide_k8s(server_exists, client_exists) {
        K8sAction::SkipExists => {
            info!(
                namespace = %namespace,
                server = %server_name,
                client = %client_name,
                "PKI secrets already exist, skipping."
            );
            return Ok(());
        }
        K8sAction::PartialState => {
            return Err(miette::miette!(
                "partial PKI state in namespace {namespace}: exactly one of \
                 {server_name} / {client_name} exists. Recover with: \
                 kubectl delete secret -n {namespace} {server_name} {client_name}",
            ));
        }
        K8sAction::Create => {}
    }

    let server_secret = tls_secret(
        server_name,
        &bundle.server_cert_pem,
        &bundle.server_key_pem,
        &bundle.ca_cert_pem,
    );
    let client_secret = tls_secret(
        client_name,
        &bundle.client_cert_pem,
        &bundle.client_key_pem,
        &bundle.ca_cert_pem,
    );

    api.create(&PostParams::default(), &server_secret)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create secret {server_name}"))?;
    api.create(&PostParams::default(), &client_secret)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create secret {client_name}"))?;

    info!(
        namespace = %namespace,
        server = %server_name,
        client = %client_name,
        "PKI secrets created."
    );
    Ok(())
}

fn tls_secret(name: &str, crt_pem: &str, key_pem: &str, ca_pem: &str) -> Secret {
    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        ByteString(crt_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_string(),
        ByteString(key_pem.as_bytes().to_vec()),
    );
    data.insert("ca.crt".to_string(), ByteString(ca_pem.as_bytes().to_vec()));
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".to_string()),
        data: Some(data),
        ..Default::default()
    }
}

// ─────────────────────────────── Local mode ───────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum LocalAction {
    Skip,
    PartialState,
    Create,
}

/// Layout under `<dir>` matches `deploy/rpm/init-pki.sh`:
///
/// ```text
/// <dir>/ca.crt
/// <dir>/ca.key
/// <dir>/server/tls.crt
/// <dir>/server/tls.key
/// <dir>/client/tls.crt
/// <dir>/client/tls.key
/// ```
struct LocalPaths {
    ca_crt: PathBuf,
    ca_key: PathBuf,
    server_dir: PathBuf,
    server_crt: PathBuf,
    server_key: PathBuf,
    client_dir: PathBuf,
    client_crt: PathBuf,
    client_key: PathBuf,
}

impl LocalPaths {
    fn resolve(dir: &Path) -> Self {
        let server_dir = dir.join("server");
        let client_dir = dir.join("client");
        Self {
            ca_crt: dir.join("ca.crt"),
            ca_key: dir.join("ca.key"),
            server_crt: server_dir.join("tls.crt"),
            server_key: server_dir.join("tls.key"),
            server_dir,
            client_crt: client_dir.join("tls.crt"),
            client_key: client_dir.join("tls.key"),
            client_dir,
        }
    }

    fn all_files(&self) -> [&Path; 6] {
        [
            &self.ca_crt,
            &self.ca_key,
            &self.server_crt,
            &self.server_key,
            &self.client_crt,
            &self.client_key,
        ]
    }

    fn existence_count(&self) -> usize {
        self.all_files().iter().filter(|p| p.exists()).count()
    }
}

fn decide_local(present: usize) -> LocalAction {
    match present {
        6 => LocalAction::Skip,
        0 => LocalAction::Create,
        _ => LocalAction::PartialState,
    }
}

fn run_local(dir: &Path, server_sans: &[String]) -> Result<()> {
    let paths = LocalPaths::resolve(dir);

    let bundle = match decide_local(paths.existence_count()) {
        LocalAction::Skip => {
            info!(dir = %dir.display(), "PKI files already exist, skipping.");
            read_local_bundle(&paths)?
        }
        LocalAction::PartialState => {
            return Err(miette::miette!(
                "partial PKI state in {dir}: some files exist but not all. \
                 Recover with: rm -rf {dir} (the gateway will regenerate on next start)",
                dir = dir.display(),
            ));
        }
        LocalAction::Create => {
            let bundle = generate_pki(server_sans)?;
            write_local_bundle(dir, &bundle, &paths)?;
            info!(dir = %dir.display(), "PKI files created.");
            bundle
        }
    };

    // Always make sure the CLI auto-discovery copy is in place. This
    // self-heals the case where the operator wiped ~/.config/openshell but
    // left the gateway state directory intact.
    if let Err(e) = openshell_bootstrap::mtls::store_pki_bundle("openshell", &bundle) {
        warn!(error = %e, "failed to copy client mTLS materials for CLI auto-discovery");
    }

    Ok(())
}

fn read_local_bundle(paths: &LocalPaths) -> Result<PkiBundle> {
    Ok(PkiBundle {
        ca_cert_pem: read_pem(&paths.ca_crt)?,
        ca_key_pem: read_pem(&paths.ca_key)?,
        server_cert_pem: read_pem(&paths.server_crt)?,
        server_key_pem: read_pem(&paths.server_key)?,
        client_cert_pem: read_pem(&paths.client_crt)?,
        client_key_pem: read_pem(&paths.client_key)?,
    })
}

fn read_pem(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))
}

fn write_local_bundle(dir: &Path, bundle: &PkiBundle, paths: &LocalPaths) -> Result<()> {
    // Stage to a sibling tmp dir so individual renames into the final layout
    // are atomic on the same filesystem.
    let temp = sibling_temp_dir(dir);
    if temp.exists() {
        std::fs::remove_dir_all(&temp)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {}", temp.display()))?;
    }

    let temp_server = temp.join("server");
    let temp_client = temp.join("client");
    create_dir_restricted(&temp)?;
    create_dir_restricted(&temp_server)?;
    create_dir_restricted(&temp_client)?;

    write_pem(&temp.join("ca.crt"), &bundle.ca_cert_pem, false)?;
    write_pem(&temp.join("ca.key"), &bundle.ca_key_pem, true)?;
    write_pem(&temp_server.join("tls.crt"), &bundle.server_cert_pem, false)?;
    write_pem(&temp_server.join("tls.key"), &bundle.server_key_pem, true)?;
    write_pem(&temp_client.join("tls.crt"), &bundle.client_cert_pem, false)?;
    write_pem(&temp_client.join("tls.key"), &bundle.client_key_pem, true)?;

    // Final destination (might not exist yet on first run).
    create_dir_restricted(dir)?;
    create_dir_restricted(&paths.server_dir)?;
    create_dir_restricted(&paths.client_dir)?;

    let renames: [(PathBuf, &Path); 6] = [
        (temp.join("ca.crt"), paths.ca_crt.as_path()),
        (temp.join("ca.key"), paths.ca_key.as_path()),
        (temp_server.join("tls.crt"), paths.server_crt.as_path()),
        (temp_server.join("tls.key"), paths.server_key.as_path()),
        (temp_client.join("tls.crt"), paths.client_crt.as_path()),
        (temp_client.join("tls.key"), paths.client_key.as_path()),
    ];
    for (from, to) in &renames {
        std::fs::rename(from, to)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to move {} -> {}", from.display(), to.display()))?;
    }

    let _ = std::fs::remove_dir_all(&temp);
    Ok(())
}

fn write_pem(path: &Path, contents: &str, owner_only: bool) -> Result<()> {
    std::fs::write(path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", path.display()))?;
    if owner_only {
        set_file_owner_only(path)?;
    }
    Ok(())
}

fn sibling_temp_dir(dir: &Path) -> PathBuf {
    // Use a sibling so std::fs::rename succeeds (same filesystem).
    let mut name = dir
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".certgen.tmp");
    dir.with_file_name(name)
}

// ────────────────────────────── Shared utility ─────────────────────────────

fn print_bundle(bundle: &PkiBundle) {
    println!("# CA certificate\n{}", bundle.ca_cert_pem);
    println!("# Server certificate\n{}", bundle.server_cert_pem);
    println!("# Server key\n{}", bundle.server_key_pem);
    println!("# Client certificate\n{}", bundle.client_cert_pem);
    println!("# Client key\n{}", bundle.client_key_pem);
}

#[cfg(test)]
mod tests {
    use super::{
        K8sAction, LocalAction, LocalPaths, decide_k8s, decide_local, read_local_bundle,
        sibling_temp_dir, tls_secret, write_local_bundle,
    };
    use openshell_bootstrap::pki::generate_pki;
    use std::path::Path;

    // ── Kubernetes-mode decision ──

    #[test]
    fn decide_k8s_skip_when_both_exist() {
        assert_eq!(decide_k8s(true, true), K8sAction::SkipExists);
    }

    #[test]
    fn decide_k8s_create_when_neither_exists() {
        assert_eq!(decide_k8s(false, false), K8sAction::Create);
    }

    #[test]
    fn decide_k8s_partial_when_only_server_exists() {
        assert_eq!(decide_k8s(true, false), K8sAction::PartialState);
    }

    #[test]
    fn decide_k8s_partial_when_only_client_exists() {
        assert_eq!(decide_k8s(false, true), K8sAction::PartialState);
    }

    #[test]
    fn tls_secret_has_kubernetes_io_tls_type_and_three_keys() {
        let s = tls_secret("foo", "CRT-PEM", "KEY-PEM", "CA-PEM");
        assert_eq!(s.metadata.name.as_deref(), Some("foo"));
        assert_eq!(s.type_.as_deref(), Some("kubernetes.io/tls"));
        let data = s.data.expect("data set");
        assert_eq!(data.len(), 3);
        assert_eq!(data["tls.crt"].0, b"CRT-PEM");
        assert_eq!(data["tls.key"].0, b"KEY-PEM");
        assert_eq!(data["ca.crt"].0, b"CA-PEM");
    }

    // ── Local-mode decision ──

    #[test]
    fn decide_local_skip_when_all_six_present() {
        assert_eq!(decide_local(6), LocalAction::Skip);
    }

    #[test]
    fn decide_local_create_when_none_present() {
        assert_eq!(decide_local(0), LocalAction::Create);
    }

    #[test]
    fn decide_local_partial_for_any_count_in_between() {
        for n in 1..=5 {
            assert_eq!(decide_local(n), LocalAction::PartialState, "n = {n}");
        }
    }

    // ── Local-mode layout & writes ──

    #[test]
    fn local_paths_resolve_matches_init_pki_layout() {
        let p = LocalPaths::resolve(Path::new("/tmp/openshell/tls"));
        assert_eq!(p.ca_crt, Path::new("/tmp/openshell/tls/ca.crt"));
        assert_eq!(p.ca_key, Path::new("/tmp/openshell/tls/ca.key"));
        assert_eq!(p.server_crt, Path::new("/tmp/openshell/tls/server/tls.crt"));
        assert_eq!(p.server_key, Path::new("/tmp/openshell/tls/server/tls.key"));
        assert_eq!(p.client_crt, Path::new("/tmp/openshell/tls/client/tls.crt"));
        assert_eq!(p.client_key, Path::new("/tmp/openshell/tls/client/tls.key"));
    }

    #[test]
    fn sibling_temp_dir_is_adjacent_to_target() {
        assert_eq!(
            sibling_temp_dir(Path::new("/var/lib/openshell/tls")),
            Path::new("/var/lib/openshell/tls.certgen.tmp")
        );
    }

    #[test]
    fn write_local_bundle_writes_six_files_and_removes_temp() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &bundle, &paths).expect("write_local_bundle");

        for f in paths.all_files() {
            assert!(f.is_file(), "missing {}", f.display());
        }
        assert!(
            !sibling_temp_dir(&dir).exists(),
            "temp dir should be cleaned up"
        );

        // Spot-check contents.
        let ca = std::fs::read_to_string(&paths.ca_crt).unwrap();
        assert!(ca.contains("BEGIN CERTIFICATE"));
        let server_key = std::fs::read_to_string(&paths.server_key).unwrap();
        assert!(server_key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn read_local_bundle_uses_existing_files() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &bundle, &paths).expect("write_local_bundle");

        let read = read_local_bundle(&paths).expect("read_local_bundle");
        assert_eq!(read.ca_cert_pem, bundle.ca_cert_pem);
        assert_eq!(read.client_cert_pem, bundle.client_cert_pem);
        assert_eq!(read.client_key_pem, bundle.client_key_pem);
    }

    #[cfg(unix)]
    #[test]
    fn write_local_bundle_sets_owner_only_on_keys() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &bundle, &paths).expect("write_local_bundle");

        for key in [&paths.ca_key, &paths.server_key, &paths.client_key] {
            let mode = std::fs::metadata(key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key {} has mode {:o}", key.display(), mode);
        }
    }

    #[test]
    fn write_local_bundle_recovers_from_stale_temp_dir() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let stale = sibling_temp_dir(&dir);
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("garbage"), "stale").unwrap();

        let bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);
        write_local_bundle(&dir, &bundle, &paths).expect("write_local_bundle");

        assert!(paths.ca_crt.is_file());
        assert!(!stale.exists(), "stale temp dir should be removed");
    }
}
