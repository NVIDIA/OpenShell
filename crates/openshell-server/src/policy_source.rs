// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup loader for governed policy and provider profile documents.

use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use openshell_core::proto::SandboxPolicy;
use openshell_core::proto::policy_source::v1::policy_source_client::PolicySourceClient as GrpcPolicySourceClient;
use openshell_core::proto::policy_source::v1::{GetDocumentRequest, ListDocumentsRequest};
use openshell_core::{Error, Result};
use openshell_providers::parse_profile_yaml;
use sha2::{Digest, Sha256};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use tracing::info;

use crate::config_file::GatewayPoliciesSection;
use crate::grpc::provider::upsert_source_provider_profile;
use crate::grpc::validation::validate_policy_safety;
use crate::persistence::{Store, WriteCondition};

const SOURCE_DOCUMENT_OBJECT_TYPE: &str = "policy_source_document";
const POLICY_KIND: &str = "policy";
const PROVIDER_KIND: &str = "provider";

#[derive(Debug, Clone)]
pub(crate) struct LoadedPolicySource {
    pub(crate) default_policy: Option<SandboxPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicySourceLocation {
    File(PathBuf),
    GrpcUnix(PathBuf),
}

struct SourceYamlDocument {
    name: String,
    bytes: Vec<u8>,
    digest_hex: String,
}

enum PolicySourceConnection {
    File(FilePolicySource),
    Grpc(GrpcPolicySource),
}

struct FilePolicySource {
    root: PathBuf,
}

struct GrpcPolicySource {
    client: GrpcPolicySourceClient<Channel>,
}

pub(crate) async fn load_policy_source(
    store: &Store,
    config: Option<&GatewayPoliciesSection>,
) -> Result<Option<LoadedPolicySource>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let location = config
        .location
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let default_policy_name = config
        .default_policy
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(location) = location else {
        if default_policy_name.is_some() {
            return Err(Error::config(
                "[openshell.gateway.policies].location is required when default_policy is set",
            ));
        }
        return Ok(None);
    };

    let mut source = PolicySourceConnection::connect(location).await?;

    let mut policy_names = source.list_policies().await?;
    if let Some(default_name) = default_policy_name
        && !policy_names.iter().any(|name| name == default_name)
    {
        policy_names.push(default_name.to_string());
    }
    policy_names.sort();
    policy_names.dedup();

    let mut default_policy = None;
    for name in &policy_names {
        validate_document_name(POLICY_KIND, name)?;
        let document = source.get_policy(name).await?;
        let policy = parse_policy_document(&document)?;
        persist_source_document(store, POLICY_KIND, &document).await?;
        if default_policy_name.is_some_and(|default_name| default_name == name) {
            default_policy = Some(policy);
        }
    }

    if let Some(default_name) = default_policy_name
        && default_policy.is_none()
    {
        return Err(Error::config(format!(
            "default policy '{default_name}' was not loaded from policy source"
        )));
    }

    let mut provider_names = source.list_providers().await?;
    provider_names.sort();
    provider_names.dedup();
    for name in &provider_names {
        validate_document_name(PROVIDER_KIND, name)?;
        let document = source.get_provider(name).await?;
        let profile = parse_provider_document(&document)?;
        persist_source_document(store, PROVIDER_KIND, &document).await?;
        upsert_source_provider_profile(
            store,
            &format!("policy-source/{PROVIDER_KIND}/{}", document.name),
            profile,
            &document.digest_hex,
        )
        .await
        .map_err(|status| Error::config(format!("provider profile source error: {status}")))?;
    }

    info!(
        policies = policy_names.len(),
        providers = provider_names.len(),
        default_policy = default_policy_name.unwrap_or(""),
        "policy source loaded"
    );
    Ok(Some(LoadedPolicySource { default_policy }))
}

impl PolicySourceConnection {
    async fn connect(location: &str) -> Result<Self> {
        match parse_policy_source_location(location)? {
            PolicySourceLocation::File(root) => Ok(Self::File(FilePolicySource { root })),
            PolicySourceLocation::GrpcUnix(socket_path) => {
                Ok(Self::Grpc(GrpcPolicySource::connect(socket_path).await?))
            }
        }
    }

    async fn list_policies(&mut self) -> Result<Vec<String>> {
        match self {
            Self::File(source) => source.list_documents("policies").await,
            Self::Grpc(source) => source.list_policies().await,
        }
    }

    async fn get_policy(&mut self, name: &str) -> Result<SourceYamlDocument> {
        match self {
            Self::File(source) => source.get_document("policies", name).await,
            Self::Grpc(source) => source.get_policy(name).await,
        }
    }

    async fn list_providers(&mut self) -> Result<Vec<String>> {
        match self {
            Self::File(source) => source.list_documents("providers").await,
            Self::Grpc(source) => source.list_providers().await,
        }
    }

    async fn get_provider(&mut self, name: &str) -> Result<SourceYamlDocument> {
        match self {
            Self::File(source) => source.get_document("providers", name).await,
            Self::Grpc(source) => source.get_provider(name).await,
        }
    }
}

impl FilePolicySource {
    async fn list_documents(&self, directory: &str) -> Result<Vec<String>> {
        let path = self.root.join(directory);
        let mut entries = match tokio::fs::read_dir(&path).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(Error::config(format!(
                    "failed to read policy source directory {}: {err}",
                    path.display()
                )));
            }
        };

        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|err| {
            Error::config(format!(
                "failed to read policy source directory {}: {err}",
                path.display()
            ))
        })? {
            if !entry
                .file_type()
                .await
                .map_err(|err| {
                    Error::config(format!(
                        "failed to inspect policy source entry {}: {err}",
                        entry.path().display()
                    ))
                })?
                .is_file()
            {
                continue;
            }
            let path = entry.path();
            if !is_yaml_path(&path) {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    Error::config(format!(
                        "policy source file {} does not have a valid UTF-8 name",
                        path.display()
                    ))
                })?
                .to_string();
            validate_document_name("file", &name)?;
            names.push(name);
        }

        names.sort();
        for window in names.windows(2) {
            if window[0] == window[1] {
                return Err(Error::config(format!(
                    "policy source directory {} contains duplicate YAML documents named '{}'",
                    path.display(),
                    window[0]
                )));
            }
        }
        Ok(names)
    }

    async fn get_document(&self, directory: &str, name: &str) -> Result<SourceYamlDocument> {
        validate_document_name("file", name)?;
        let mut matches = Vec::new();
        for extension in ["yaml", "yml"] {
            let path = self
                .root
                .join(directory)
                .join(format!("{name}.{extension}"));
            match tokio::fs::metadata(&path).await {
                Ok(metadata) if metadata.is_file() => matches.push(path),
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(Error::config(format!(
                        "failed to inspect policy source file {}: {err}",
                        path.display()
                    )));
                }
            }
        }
        if matches.is_empty() {
            return Err(Error::config(format!(
                "policy source document '{name}' not found under {}",
                self.root.join(directory).display()
            )));
        }
        if matches.len() > 1 {
            return Err(Error::config(format!(
                "policy source document '{name}' exists as both .yaml and .yml"
            )));
        }

        let bytes = tokio::fs::read(&matches[0]).await.map_err(|err| {
            Error::config(format!(
                "failed to read policy source file {}: {err}",
                matches[0].display()
            ))
        })?;
        Ok(source_yaml_document(name, bytes))
    }
}

impl GrpcPolicySource {
    async fn connect(socket_path: PathBuf) -> Result<Self> {
        let connector_path = socket_path.clone();
        let channel = Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
                let socket_path = connector_path.clone();
                async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
            }))
            .await
            .map_err(|err| {
                Error::transport(format!(
                    "failed to connect policy source socket {}: {err}",
                    socket_path.display()
                ))
            })?;
        Ok(Self {
            client: GrpcPolicySourceClient::new(channel),
        })
    }

    async fn list_policies(&mut self) -> Result<Vec<String>> {
        Ok(self
            .client
            .list_policies(ListDocumentsRequest {})
            .await
            .map_err(|status| {
                Error::config(format!("policy source ListPolicies failed: {status}"))
            })?
            .into_inner()
            .names)
    }

    async fn get_policy(&mut self, name: &str) -> Result<SourceYamlDocument> {
        self.get_document(POLICY_KIND, name).await
    }

    async fn list_providers(&mut self) -> Result<Vec<String>> {
        Ok(self
            .client
            .list_providers(ListDocumentsRequest {})
            .await
            .map_err(|status| {
                Error::config(format!("policy source ListProviders failed: {status}"))
            })?
            .into_inner()
            .names)
    }

    async fn get_provider(&mut self, name: &str) -> Result<SourceYamlDocument> {
        self.get_document(PROVIDER_KIND, name).await
    }

    async fn get_document(&mut self, kind: &str, name: &str) -> Result<SourceYamlDocument> {
        validate_document_name(kind, name)?;
        let request = GetDocumentRequest {
            name: name.to_string(),
        };
        let bytes = match kind {
            POLICY_KIND => {
                self.client
                    .get_policy(request)
                    .await
                    .map_err(|status| {
                        Error::config(format!(
                            "policy source GetPolicy('{name}') failed: {status}"
                        ))
                    })?
                    .into_inner()
                    .document
            }
            PROVIDER_KIND => {
                self.client
                    .get_provider(request)
                    .await
                    .map_err(|status| {
                        Error::config(format!(
                            "policy source GetProvider('{name}') failed: {status}"
                        ))
                    })?
                    .into_inner()
                    .document
            }
            _ => unreachable!("unknown source document kind"),
        };
        Ok(source_yaml_document(name, bytes))
    }
}

fn parse_policy_source_location(location: &str) -> Result<PolicySourceLocation> {
    let location = location.trim();
    if location.is_empty() {
        return Err(Error::config("policy source location is empty"));
    }
    if let Some(path) = location.strip_prefix("grpc+unix://") {
        if path.is_empty() {
            return Err(Error::config(
                "grpc+unix policy source location is missing a path",
            ));
        }
        return Ok(PolicySourceLocation::GrpcUnix(PathBuf::from(path)));
    }
    if let Some(path) = location.strip_prefix("file://") {
        if path.is_empty() {
            return Err(Error::config(
                "file policy source location is missing a path",
            ));
        }
        return Ok(PolicySourceLocation::File(PathBuf::from(path)));
    }
    Ok(PolicySourceLocation::File(PathBuf::from(location)))
}

fn parse_policy_document(document: &SourceYamlDocument) -> Result<SandboxPolicy> {
    let yaml = yaml_text(POLICY_KIND, document)?;
    let mut policy = openshell_policy::parse_sandbox_policy(yaml).map_err(|err| {
        Error::config(format!(
            "policy source policy '{}' is not valid YAML policy: {err}",
            document.name
        ))
    })?;
    openshell_policy::ensure_sandbox_process_identity(&mut policy);
    validate_policy_safety(&policy).map_err(|status| {
        Error::config(format!(
            "policy source policy '{}' failed safety validation: {}",
            document.name,
            status.message()
        ))
    })?;
    Ok(policy)
}

fn parse_provider_document(
    document: &SourceYamlDocument,
) -> Result<openshell_providers::ProviderTypeProfile> {
    let yaml = yaml_text(PROVIDER_KIND, document)?;
    parse_profile_yaml(yaml).map_err(|err| {
        Error::config(format!(
            "policy source provider '{}' is not valid YAML provider profile: {err}",
            document.name
        ))
    })
}

async fn persist_source_document(
    store: &Store,
    kind: &str,
    document: &SourceYamlDocument,
) -> Result<()> {
    let labels = serde_json::json!({
        "openshell.io/source": "policy-source",
        "openshell.io/source-format": "yaml",
        "openshell.io/document-kind": kind,
        "openshell.io/document-sha256": document.digest_hex,
    });
    store
        .put_if(
            SOURCE_DOCUMENT_OBJECT_TYPE,
            &source_document_id(kind, &document.name),
            &source_document_name(kind, &document.name),
            &document.bytes,
            Some(&labels.to_string()),
            WriteCondition::Unconditional,
        )
        .await
        .map_err(|err| {
            Error::execution(format!(
                "persist policy source {kind} document '{}' failed: {err}",
                document.name
            ))
        })?;
    Ok(())
}

fn source_yaml_document(name: &str, bytes: Vec<u8>) -> SourceYamlDocument {
    SourceYamlDocument {
        name: name.to_string(),
        digest_hex: sha256_hex(&bytes),
        bytes,
    }
}

fn yaml_text<'a>(kind: &str, document: &'a SourceYamlDocument) -> Result<&'a str> {
    std::str::from_utf8(&document.bytes).map_err(|err| {
        Error::config(format!(
            "policy source {kind} document '{}' is not UTF-8 YAML: {err}",
            document.name
        ))
    })
}

fn validate_document_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.trim() != name {
        return Err(Error::config(format!(
            "policy source {kind} document name must be non-empty and trimmed"
        )));
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(Error::config(format!(
            "policy source {kind} document name '{name}' must not contain path separators"
        )));
    }
    Ok(())
}

fn is_yaml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "yaml" || extension == "yml")
}

fn source_document_id(kind: &str, name: &str) -> String {
    format!("policy-source:{kind}:{name}")
}

fn source_document_name(kind: &str, name: &str) -> String {
    format!("{kind}/{name}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::provider::{
        SOURCE_PROVIDER_PROFILE_DIGEST_PREFIX_LABEL_KEY, SOURCE_PROVIDER_PROFILE_LABEL_KEY,
        SOURCE_PROVIDER_PROFILE_LABEL_VALUE,
    };
    use crate::persistence::ObjectType;
    use openshell_core::proto::StoredProviderProfile;

    #[test]
    fn parses_policy_source_locations() {
        assert_eq!(
            parse_policy_source_location("grpc+unix:///tmp/policy.sock").expect("grpc"),
            PolicySourceLocation::GrpcUnix(PathBuf::from("/tmp/policy.sock"))
        );
        assert_eq!(
            parse_policy_source_location("file:///tmp/policies").expect("file"),
            PolicySourceLocation::File(PathBuf::from("/tmp/policies"))
        );
        assert_eq!(
            parse_policy_source_location("/tmp/policies").expect("bare file"),
            PolicySourceLocation::File(PathBuf::from("/tmp/policies"))
        );
    }

    #[tokio::test]
    async fn loads_file_source_default_policy_and_provider_profile() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("policies")).expect("policies dir");
        std::fs::create_dir(root.path().join("providers")).expect("providers dir");
        std::fs::write(
            root.path().join("policies/default.yaml"),
            r#"
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: https
    binaries:
      - path: /usr/bin/curl
"#,
        )
        .expect("policy");
        std::fs::write(
            root.path().join("providers/example.yaml"),
            r#"
id: example
display_name: Example
credentials:
  - name: api_key
    env_vars: [EXAMPLE_API_KEY]
"#,
        )
        .expect("provider");

        let store = crate::persistence::test_store().await;
        let config = GatewayPoliciesSection {
            location: Some(root.path().display().to_string()),
            default_policy: Some("default".to_string()),
        };
        let loaded = load_policy_source(&store, Some(&config))
            .await
            .expect("load")
            .expect("configured");

        assert!(loaded.default_policy.is_some());
        assert!(
            store
                .get_by_name(SOURCE_DOCUMENT_OBJECT_TYPE, "policy/default")
                .await
                .expect("policy source document")
                .is_some()
        );
        let profile = store
            .get_message_by_name::<StoredProviderProfile>("example")
            .await
            .expect("provider profile")
            .expect("provider profile persisted");
        let labels = profile.metadata.expect("metadata").labels;
        assert_eq!(
            labels
                .get(SOURCE_PROVIDER_PROFILE_LABEL_KEY)
                .map(String::as_str),
            Some(SOURCE_PROVIDER_PROFILE_LABEL_VALUE)
        );
        assert!(labels.contains_key(SOURCE_PROVIDER_PROFILE_DIGEST_PREFIX_LABEL_KEY));
        assert_eq!(StoredProviderProfile::object_type(), "provider_profile");
    }
}
