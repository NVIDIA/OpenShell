// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `generate-certs` subcommand: bootstrap mTLS PKI for the gateway.
//!
//! Two output modes, dispatched by the presence of `--output-dir`:
//!
//! - **Kubernetes mode** (default): create two `kubernetes.io/tls` Secrets
//!   and one sandbox-JWT signing Secret in the supplied namespace. Used by
//!   the Helm pre-install hook. Requires `--namespace`,
//!   `--server-secret-name`, `--client-secret-name`, and `--jwt-secret-name`.
//! - **Kubernetes JWT-only mode** (`--jwt-only`): create only the
//!   sandbox-JWT signing Secret. Used when another controller, such as
//!   cert-manager, owns the TLS Secrets.
//! - **Local mode** (`--output-dir <DIR>`): write PEMs to the local package
//!   filesystem layout. Used by systemd units' `ExecStartPre`. Also copies
//!   client materials to
//!   `$XDG_CONFIG_HOME/openshell/gateways/openshell/mtls/` so the local CLI
//!   picks them up automatically.
//!
//! Both modes share the same idempotency contract: all targets present →
//! skip; legacy TLS-only state → add the JWT signing material; partial
//! state → error with a recovery hint; nothing present → generate and write.

use clap::Args;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_bootstrap::pki::{DEFAULT_SERVER_SANS, PkiBundle, generate_pki};
use openshell_core::paths::{create_dir_restricted, set_file_owner_only};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    #[arg(long, required_unless_present_any = ["output_dir", "jwt_only"])]
    server_secret_name: Option<String>,

    /// Name of the client TLS Secret (`kubernetes.io/tls`) to create.
    #[arg(long, required_unless_present_any = ["output_dir", "jwt_only"])]
    client_secret_name: Option<String>,

    /// Name of the sandbox-JWT signing-key Secret (`Opaque`) to create.
    /// Holds `signing.pem`, `public.pem`, and `kid` keys. Mounted on the
    /// gateway pod (only) so it can mint and validate per-sandbox JWTs.
    #[arg(long, required_unless_present = "output_dir")]
    jwt_secret_name: Option<String>,

    /// Create only the sandbox-JWT signing-key Secret in Kubernetes mode.
    /// This is used when another controller owns TLS Secret provisioning.
    #[arg(long, conflicts_with = "output_dir")]
    jwt_only: bool,

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
    CreateJwtOnly,
    PartialState,
    CreateAll,
}

fn decide_k8s(server_exists: bool, client_exists: bool, jwt_exists: bool) -> K8sAction {
    match (server_exists, client_exists, jwt_exists) {
        (true, true, true) => K8sAction::SkipExists,
        (true, true, false) => K8sAction::CreateJwtOnly,
        (false, false, false) => K8sAction::CreateAll,
        _ => K8sAction::PartialState,
    }
}

async fn run_kubernetes(args: &CertgenArgs, bundle: &PkiBundle) -> Result<()> {
    let namespace = args
        .namespace
        .as_deref()
        .ok_or_else(|| miette::miette!("--namespace is required (or set POD_NAMESPACE)"))?;

    let client = Client::try_default()
        .await
        .into_diagnostic()
        .wrap_err("failed to construct in-cluster Kubernetes client")?;
    let api: Api<Secret> = Api::namespaced(client, namespace);

    if args.jwt_only {
        let jwt_name = args
            .jwt_secret_name
            .as_deref()
            .ok_or_else(|| miette::miette!("--jwt-secret-name is required"))?;
        let jwt_exists = api
            .get_opt(jwt_name)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read secret {jwt_name}"))?
            .is_some();
        if jwt_exists {
            info!(
                namespace = %namespace,
                jwt = %jwt_name,
                "JWT signing secret already exists, skipping."
            );
            return Ok(());
        }

        let jwt_secret = jwt_signing_secret(
            jwt_name,
            &bundle.jwt_signing_key_pem,
            &bundle.jwt_public_key_pem,
            &bundle.jwt_key_id,
        );
        api.create(&PostParams::default(), &jwt_secret)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create secret {jwt_name}"))?;
        info!(
            namespace = %namespace,
            jwt = %jwt_name,
            "JWT signing secret created."
        );
        return Ok(());
    }

    let server_name = args
        .server_secret_name
        .as_deref()
        .ok_or_else(|| miette::miette!("--server-secret-name is required"))?;
    let client_name = args
        .client_secret_name
        .as_deref()
        .ok_or_else(|| miette::miette!("--client-secret-name is required"))?;
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

    let jwt_name = args
        .jwt_secret_name
        .as_deref()
        .ok_or_else(|| miette::miette!("--jwt-secret-name is required"))?;
    let jwt_exists = api
        .get_opt(jwt_name)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read secret {jwt_name}"))?
        .is_some();

    match decide_k8s(server_exists, client_exists, jwt_exists) {
        K8sAction::SkipExists => {
            info!(
                namespace = %namespace,
                server = %server_name,
                client = %client_name,
                jwt = %jwt_name,
                "PKI secrets already exist, skipping."
            );
            return Ok(());
        }
        K8sAction::PartialState => {
            return Err(miette::miette!(
                "partial PKI state in namespace {namespace}: only some of \
                 {server_name} / {client_name} / {jwt_name} exist. Recover with: \
                 kubectl delete secret -n {namespace} {server_name} {client_name} {jwt_name}",
            ));
        }
        K8sAction::CreateJwtOnly => {
            let jwt_secret = jwt_signing_secret(
                jwt_name,
                &bundle.jwt_signing_key_pem,
                &bundle.jwt_public_key_pem,
                &bundle.jwt_key_id,
            );
            api.create(&PostParams::default(), &jwt_secret)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create secret {jwt_name}"))?;
            info!(
                namespace = %namespace,
                jwt = %jwt_name,
                "JWT signing secret created for existing TLS install."
            );
            return Ok(());
        }
        K8sAction::CreateAll => {}
    }

    create_tls_secrets(&api, server_name, client_name, bundle).await?;
    let jwt_secret = jwt_signing_secret(
        jwt_name,
        &bundle.jwt_signing_key_pem,
        &bundle.jwt_public_key_pem,
        &bundle.jwt_key_id,
    );
    api.create(&PostParams::default(), &jwt_secret)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create secret {jwt_name}"))?;

    info!(
        namespace = %namespace,
        server = %server_name,
        client = %client_name,
        jwt = %jwt_name,
        "PKI secrets created."
    );
    Ok(())
}

async fn create_tls_secrets(
    api: &Api<Secret>,
    server_name: &str,
    client_name: &str,
    bundle: &PkiBundle,
) -> Result<()> {
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

/// Build an `Opaque` Secret carrying the gateway-minted sandbox JWT
/// signing material. Mounted only on the gateway pod — sandbox pods
/// receive a per-pod gateway-signed token, never the signing key itself.
fn jwt_signing_secret(name: &str, signing_pem: &str, public_pem: &str, kid: &str) -> Secret {
    let mut data = BTreeMap::new();
    data.insert(
        "signing.pem".to_string(),
        ByteString(signing_pem.as_bytes().to_vec()),
    );
    data.insert(
        "public.pem".to_string(),
        ByteString(public_pem.as_bytes().to_vec()),
    );
    data.insert("kid".to_string(), ByteString(kid.as_bytes().to_vec()));
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        data: Some(data),
        ..Default::default()
    }
}

// ─────────────────────────────── Local mode ───────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum LocalAction {
    Skip,
    CreateJwtOnly,
    PartialState,
    CreateAll,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CertSan {
    Dns(String),
    Ip(IpAddr),
}

impl fmt::Display for CertSan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => write!(f, "{name}"),
            Self::Ip(addr) => write!(f, "{addr}"),
        }
    }
}

/// Layout under `<dir>`:
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
    jwt_dir: PathBuf,
    jwt_signing: PathBuf,
    jwt_public: PathBuf,
    jwt_kid: PathBuf,
}

impl LocalPaths {
    fn resolve(dir: &Path) -> Self {
        let server_dir = dir.join("server");
        let client_dir = dir.join("client");
        let jwt_dir = dir.join("jwt");
        Self {
            ca_crt: dir.join("ca.crt"),
            ca_key: dir.join("ca.key"),
            server_crt: server_dir.join("tls.crt"),
            server_key: server_dir.join("tls.key"),
            server_dir,
            client_crt: client_dir.join("tls.crt"),
            client_key: client_dir.join("tls.key"),
            client_dir,
            jwt_signing: jwt_dir.join("signing.pem"),
            jwt_public: jwt_dir.join("public.pem"),
            jwt_kid: jwt_dir.join("kid"),
            jwt_dir,
        }
    }

    fn tls_files(&self) -> [&Path; 6] {
        [
            &self.ca_crt,
            &self.ca_key,
            &self.server_crt,
            &self.server_key,
            &self.client_crt,
            &self.client_key,
        ]
    }

    fn jwt_files(&self) -> [&Path; 3] {
        [&self.jwt_signing, &self.jwt_public, &self.jwt_kid]
    }

    #[cfg(test)]
    fn all_files(&self) -> [&Path; 9] {
        [
            &self.ca_crt,
            &self.ca_key,
            &self.server_crt,
            &self.server_key,
            &self.client_crt,
            &self.client_key,
            &self.jwt_signing,
            &self.jwt_public,
            &self.jwt_kid,
        ]
    }

    fn tls_existence_count(&self) -> usize {
        self.tls_files().iter().filter(|p| p.exists()).count()
    }

    fn jwt_existence_count(&self) -> usize {
        self.jwt_files().iter().filter(|p| p.exists()).count()
    }
}

fn decide_local(tls_present: usize, jwt_present: usize) -> LocalAction {
    match (tls_present, jwt_present) {
        (6, 3) => LocalAction::Skip,
        (6, 0) => LocalAction::CreateJwtOnly,
        (0, 0) => LocalAction::CreateAll,
        _ => LocalAction::PartialState,
    }
}

fn run_local(dir: &Path, server_sans: &[String]) -> Result<()> {
    let paths = LocalPaths::resolve(dir);

    let bundle = match decide_local(paths.tls_existence_count(), paths.jwt_existence_count()) {
        LocalAction::Skip => {
            let missing_sans = missing_required_server_sans(&paths, server_sans)?;
            if missing_sans.is_empty() {
                info!(dir = %dir.display(), "PKI files already exist, skipping.");
            } else {
                let bundle = generate_pki(server_sans)?;
                write_local_tls_bundle(&bundle, &paths)?;
                info!(
                    dir = %dir.display(),
                    missing_sans = %format_cert_sans(&missing_sans),
                    "server TLS certificate refreshed for current SAN set.",
                );
            }
            read_local_bundle(&paths)?
        }
        LocalAction::CreateJwtOnly => {
            let bundle = generate_pki(server_sans)?;
            let missing_sans = missing_required_server_sans(&paths, server_sans)?;
            if missing_sans.is_empty() {
                write_local_jwt_bundle(&bundle, &paths)?;
                info!(dir = %dir.display(), "JWT signing files created for existing TLS install.");
            } else {
                write_local_bundle(dir, &bundle, &paths)?;
                info!(
                    dir = %dir.display(),
                    missing_sans = %format_cert_sans(&missing_sans),
                    "PKI files refreshed for current SAN set and JWT signing material.",
                );
            }
            read_local_bundle(&paths)?
        }
        LocalAction::PartialState => {
            return Err(miette::miette!(
                "partial PKI state in {dir}: some files exist but not all. \
                 Recover with: rm -rf {dir} (the gateway will regenerate on next start)",
                dir = dir.display(),
            ));
        }
        LocalAction::CreateAll => {
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

fn required_server_sans(server_sans: &[String]) -> BTreeSet<CertSan> {
    DEFAULT_SERVER_SANS
        .iter()
        .copied()
        .chain(server_sans.iter().map(String::as_str))
        .filter_map(|san| {
            san.parse::<IpAddr>()
                .map(CertSan::Ip)
                .ok()
                .or_else(|| san.is_ascii().then(|| CertSan::Dns(san.to_string())))
        })
        .collect()
}

fn missing_required_server_sans(
    paths: &LocalPaths,
    server_sans: &[String],
) -> Result<Vec<CertSan>> {
    let required = required_server_sans(server_sans);
    let actual = server_cert_sans(&paths.server_crt)?;
    Ok(required.difference(&actual).cloned().collect())
}

fn server_cert_sans(path: &Path) -> Result<BTreeSet<CertSan>> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let pem = std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", path.display()))?;
    let (_, pem) = parse_x509_pem(&pem).map_err(|e| {
        miette::miette!(
            "failed to parse server certificate PEM {}: {e:?}",
            path.display()
        )
    })?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|e| {
        miette::miette!(
            "failed to parse server certificate {}: {e:?}",
            path.display()
        )
    })?;

    let Some(ext) = cert.subject_alternative_name().map_err(|e| {
        miette::miette!(
            "failed to read server certificate SANs {}: {e:?}",
            path.display()
        )
    })?
    else {
        return Ok(BTreeSet::new());
    };

    let mut sans = BTreeSet::new();
    for name in &ext.value.general_names {
        match name {
            GeneralName::DNSName(name) => {
                sans.insert(CertSan::Dns((*name).to_string()));
            }
            GeneralName::IPAddress(raw) => match raw.len() {
                4 => {
                    sans.insert(CertSan::Ip(IpAddr::V4(Ipv4Addr::new(
                        raw[0], raw[1], raw[2], raw[3],
                    ))));
                }
                16 => {
                    let octets: [u8; 16] = (*raw).try_into().expect("checked IPv6 SAN length");
                    sans.insert(CertSan::Ip(IpAddr::V6(Ipv6Addr::from(octets))));
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(sans)
}

fn format_cert_sans(sans: &[CertSan]) -> String {
    sans.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn read_local_bundle(paths: &LocalPaths) -> Result<PkiBundle> {
    Ok(PkiBundle {
        ca_cert_pem: read_pem(&paths.ca_crt)?,
        ca_key_pem: read_pem(&paths.ca_key)?,
        server_cert_pem: read_pem(&paths.server_crt)?,
        server_key_pem: read_pem(&paths.server_key)?,
        client_cert_pem: read_pem(&paths.client_crt)?,
        client_key_pem: read_pem(&paths.client_key)?,
        jwt_signing_key_pem: read_pem(&paths.jwt_signing)?,
        jwt_public_key_pem: read_pem(&paths.jwt_public)?,
        jwt_key_id: read_pem(&paths.jwt_kid)?.trim().to_string(),
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
    let temp_jwt = temp.join("jwt");
    create_dir_restricted(&temp)?;
    create_dir_restricted(&temp_server)?;
    create_dir_restricted(&temp_client)?;
    create_dir_restricted(&temp_jwt)?;

    write_pem(&temp.join("ca.crt"), &bundle.ca_cert_pem, false)?;
    write_pem(&temp.join("ca.key"), &bundle.ca_key_pem, true)?;
    write_pem(&temp_server.join("tls.crt"), &bundle.server_cert_pem, false)?;
    write_pem(&temp_server.join("tls.key"), &bundle.server_key_pem, true)?;
    write_pem(&temp_client.join("tls.crt"), &bundle.client_cert_pem, false)?;
    write_pem(&temp_client.join("tls.key"), &bundle.client_key_pem, true)?;
    write_pem(
        &temp_jwt.join("signing.pem"),
        &bundle.jwt_signing_key_pem,
        true,
    )?;
    write_pem(
        &temp_jwt.join("public.pem"),
        &bundle.jwt_public_key_pem,
        false,
    )?;
    write_pem(&temp_jwt.join("kid"), &bundle.jwt_key_id, false)?;

    // Final destination (might not exist yet on first run).
    create_dir_restricted(dir)?;
    create_dir_restricted(&paths.server_dir)?;
    create_dir_restricted(&paths.client_dir)?;
    create_dir_restricted(&paths.jwt_dir)?;

    let renames: [(PathBuf, &Path); 9] = [
        (temp.join("ca.crt"), paths.ca_crt.as_path()),
        (temp.join("ca.key"), paths.ca_key.as_path()),
        (temp_server.join("tls.crt"), paths.server_crt.as_path()),
        (temp_server.join("tls.key"), paths.server_key.as_path()),
        (temp_client.join("tls.crt"), paths.client_crt.as_path()),
        (temp_client.join("tls.key"), paths.client_key.as_path()),
        (temp_jwt.join("signing.pem"), paths.jwt_signing.as_path()),
        (temp_jwt.join("public.pem"), paths.jwt_public.as_path()),
        (temp_jwt.join("kid"), paths.jwt_kid.as_path()),
    ];
    for (from, to) in &renames {
        std::fs::rename(from, to)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to move {} -> {}", from.display(), to.display()))?;
    }

    let _ = std::fs::remove_dir_all(&temp);
    Ok(())
}

fn write_local_tls_bundle(bundle: &PkiBundle, paths: &LocalPaths) -> Result<()> {
    let temp = sibling_temp_dir(&paths.server_dir);
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

fn write_local_jwt_bundle(bundle: &PkiBundle, paths: &LocalPaths) -> Result<()> {
    let temp = sibling_temp_dir(&paths.jwt_dir);
    if temp.exists() {
        std::fs::remove_dir_all(&temp)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove stale {}", temp.display()))?;
    }

    create_dir_restricted(&temp)?;
    write_pem(&temp.join("signing.pem"), &bundle.jwt_signing_key_pem, true)?;
    write_pem(&temp.join("public.pem"), &bundle.jwt_public_key_pem, false)?;
    write_pem(&temp.join("kid"), &bundle.jwt_key_id, false)?;

    create_dir_restricted(&paths.jwt_dir)?;
    let renames: [(PathBuf, &Path); 3] = [
        (temp.join("signing.pem"), paths.jwt_signing.as_path()),
        (temp.join("public.pem"), paths.jwt_public.as_path()),
        (temp.join("kid"), paths.jwt_kid.as_path()),
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
        CertSan, K8sAction, LocalAction, LocalPaths, decide_k8s, decide_local, jwt_signing_secret,
        missing_required_server_sans, read_local_bundle, sibling_temp_dir, tls_secret,
        write_local_bundle, write_local_jwt_bundle, write_local_tls_bundle,
    };
    use openshell_bootstrap::pki::generate_pki;
    use std::path::Path;

    // ── Kubernetes-mode decision ──

    #[test]
    fn decide_k8s_skip_when_all_three_exist() {
        assert_eq!(decide_k8s(true, true, true), K8sAction::SkipExists);
    }

    #[test]
    fn decide_k8s_create_when_none_exist() {
        assert_eq!(decide_k8s(false, false, false), K8sAction::CreateAll);
    }

    #[test]
    fn decide_k8s_creates_jwt_only_for_existing_tls() {
        assert_eq!(decide_k8s(true, true, false), K8sAction::CreateJwtOnly);
    }

    #[test]
    fn decide_k8s_partial_for_any_mixed_state() {
        let mixes = [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, false, true),
            (false, true, true),
        ];
        for (s, c, j) in mixes {
            assert_eq!(
                decide_k8s(s, c, j),
                K8sAction::PartialState,
                "({s},{c},{j})"
            );
        }
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

    #[test]
    fn jwt_signing_secret_has_opaque_type_and_three_keys() {
        let s = jwt_signing_secret("jwt", "SIGN", "PUB", "kid-1");
        assert_eq!(s.metadata.name.as_deref(), Some("jwt"));
        assert_eq!(s.type_.as_deref(), Some("Opaque"));
        let data = s.data.expect("data set");
        assert_eq!(data.len(), 3);
        assert_eq!(data["signing.pem"].0, b"SIGN");
        assert_eq!(data["public.pem"].0, b"PUB");
        assert_eq!(data["kid"].0, b"kid-1");
    }

    // ── Local-mode decision ──

    #[test]
    fn decide_local_skip_when_all_nine_present() {
        assert_eq!(decide_local(6, 3), LocalAction::Skip);
    }

    #[test]
    fn decide_local_create_when_none_present() {
        assert_eq!(decide_local(0, 0), LocalAction::CreateAll);
    }

    #[test]
    fn decide_local_creates_jwt_only_for_existing_tls() {
        assert_eq!(decide_local(6, 0), LocalAction::CreateJwtOnly);
    }

    #[test]
    fn decide_local_partial_for_incomplete_tls_or_jwt_sets() {
        for tls in 0..=6 {
            for jwt in 0..=3 {
                if matches!((tls, jwt), (6, 3 | 0) | (0, 0)) {
                    continue;
                }
                assert_eq!(
                    decide_local(tls, jwt),
                    LocalAction::PartialState,
                    "tls={tls} jwt={jwt}"
                );
            }
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
    fn write_local_jwt_bundle_preserves_existing_tls_files() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let old_bundle = generate_pki(&[]).expect("generate_pki");
        let new_bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &old_bundle, &paths).expect("write_local_bundle");
        std::fs::remove_dir_all(&paths.jwt_dir).expect("remove jwt dir");

        write_local_jwt_bundle(&new_bundle, &paths).expect("write_local_jwt_bundle");

        let read = read_local_bundle(&paths).expect("read_local_bundle");
        assert_eq!(read.ca_cert_pem, old_bundle.ca_cert_pem);
        assert_eq!(read.server_cert_pem, old_bundle.server_cert_pem);
        assert_eq!(read.client_cert_pem, old_bundle.client_cert_pem);
        assert_eq!(read.jwt_key_id, new_bundle.jwt_key_id);
        assert_eq!(read.jwt_public_key_pem, new_bundle.jwt_public_key_pem);
    }

    #[test]
    fn write_local_tls_bundle_preserves_existing_jwt_files() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let old_bundle = generate_pki(&[]).expect("generate_pki");
        let new_bundle = generate_pki(&["extra.example.test".to_string()]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &old_bundle, &paths).expect("write_local_bundle");
        write_local_tls_bundle(&new_bundle, &paths).expect("write_local_tls_bundle");

        let read = read_local_bundle(&paths).expect("read_local_bundle");
        assert_eq!(read.ca_cert_pem, new_bundle.ca_cert_pem);
        assert_eq!(read.server_cert_pem, new_bundle.server_cert_pem);
        assert_eq!(read.client_cert_pem, new_bundle.client_cert_pem);
        assert_eq!(read.jwt_key_id, old_bundle.jwt_key_id);
        assert_eq!(read.jwt_public_key_pem, old_bundle.jwt_public_key_pem);
    }

    #[test]
    fn missing_required_server_sans_detects_new_required_name() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("tls");
        let bundle = generate_pki(&[]).expect("generate_pki");
        let paths = LocalPaths::resolve(&dir);

        write_local_bundle(&dir, &bundle, &paths).expect("write_local_bundle");

        assert!(
            missing_required_server_sans(&paths, &[])
                .unwrap()
                .is_empty()
        );

        let missing =
            missing_required_server_sans(&paths, &["future.example.test".to_string()]).unwrap();
        assert_eq!(
            missing,
            vec![CertSan::Dns("future.example.test".to_string())]
        );
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
