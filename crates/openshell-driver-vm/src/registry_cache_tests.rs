// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use oci_client::client::ClientProtocol;
use oci_client::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE;
use tokio::io::AsyncReadExt as _;

/// A loopback registry with independent HEAD identity and GET contents. Blob
/// requests deliberately fail, so a rejected manifest needs no VM or formatter.
struct Registry {
    address: String,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    server: JoinHandle<()>,
}

impl Registry {
    async fn start(
        head_digest: String,
        manifests: HashMap<String, Vec<u8>>,
        get_digest: Option<String>,
        mut retry_once: bool,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 16 * 1024);
                }
                let request = String::from_utf8(request).unwrap();
                let mut parts = request.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                recorded.lock().unwrap().push(format!("{method} {path}"));
                let manifest = path.strip_prefix("/v2/test/image/manifests/");
                let mut digest = None;
                let (status, body) = if path == "/v2/" {
                    ("200 OK", b"{}".as_slice())
                } else if manifest.is_some() && method == "HEAD" {
                    digest = Some(head_digest.clone());
                    ("200 OK", b"".as_slice())
                } else if let Some(body) = manifest.and_then(|key| manifests.get(key)) {
                    if retry_once {
                        retry_once = false;
                        ("503 Service Unavailable", b"retry".as_slice())
                    } else {
                        digest = Some(get_digest.clone().unwrap_or_else(|| sha256(body)));
                        ("200 OK", body.as_slice())
                    }
                } else {
                    ("404 Not Found", b"fixture has no blob".as_slice())
                };
                let digest_header = digest.map_or_else(String::new, |value| {
                    format!("Docker-Content-Digest: {value}\r\n")
                });
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{digest_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            requests,
            server,
        }
    }

    fn reference(&self, digest: Option<&str>) -> String {
        let suffix = digest.map_or_else(|| ":latest".to_string(), |value| format!("@{value}"));
        format!("{}/test/image{suffix}", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn client() -> OciClient {
    OciClient::new(ClientConfig {
        protocol: ClientProtocol::Http,
        platform_resolver: Some(Box::new(linux_platform_resolver)),
        no_proxy: Some("*".to_string()),
        read_timeout: Some(Duration::from_secs(5)),
        connect_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
}

fn sha256(body: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(body))
}

fn manifest(label: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MEDIA_TYPE,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": sha256(label.as_bytes()),
            "size": label.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": sha256(label.as_bytes()),
            "size": label.len(),
        }],
    }))
    .unwrap()
}

fn index(body: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
        "manifests": [{
            "mediaType": OCI_IMAGE_MEDIA_TYPE,
            "digest": sha256(body),
            "size": body.len(),
            "platform": { "os": "linux", "architecture": linux_oci_arch() },
        }],
    }))
    .unwrap()
}

fn driver(root: &Path) -> VmDriver {
    let socket_root_fd = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    VmDriver {
        config: VmDriverConfig {
            state_dir: root.to_path_buf(),
            ..Default::default()
        },
        socket_root: root.to_path_buf(),
        socket_root_fd: Arc::new(socket_root_fd),
        launcher_bin: root.join("unused-vm-launcher"),
        registry: Arc::new(Mutex::new(HashMap::new())),
        image_cache_lock: Arc::new(Mutex::new(())),
        preparation_root: None,
        events: broadcast::channel(WATCH_BUFFER).0,
        gpu_inventory: None,
        lifecycle_extensions: Arc::new(LifecycleExtensionRegistry::new()),
    }
}

async fn ensure_image(
    driver: &VmDriver,
    image_ref: &str,
    client: &OciClient,
    bootstrap: bool,
) -> Result<String, Status> {
    if bootstrap {
        driver
            .ensure_cached_registry_rootfs_image(
                "test",
                image_ref,
                client,
                &RegistryAuth::Anonymous,
            )
            .await
    } else {
        driver
            .ensure_prepared_registry_image_disk(
                "test",
                image_ref,
                Path::new("unused"),
                client,
                &RegistryAuth::Anonymous,
            )
            .await
            .map(|prepared| prepared.image_identity)
    }
}

async fn rejects_unbound_manifest(bootstrap: bool) {
    // The GET body and its header agree with each other, but not with HEAD.
    // Before the fix this passed manifest verification and requested blobs.
    let trusted = manifest("trusted");
    let replacement = manifest("replacement");
    let trusted_digest = sha256(&trusted);
    let registry = Registry::start(
        trusted_digest.clone(),
        HashMap::from([
            ("latest".to_string(), replacement.clone()),
            (trusted_digest.clone(), replacement),
        ]),
        None,
        false,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let driver = driver(root.path());
    let identity = if bootstrap {
        bootstrap_image_cache_identity(&trusted_digest)
    } else {
        prepared_image_cache_identity(&trusted_digest, &driver.config)
    };
    // An upgrade must not silently reuse an entry populated by older code.
    let legacy_identity = if bootstrap {
        format!(
            "sandbox-bootstrap-rootfs-ext4-v5:openshell-{}:guest-{}:{trusted_digest}",
            openshell_core::VERSION,
            sandbox_guest_runtime_identity(),
        )
    } else {
        format!(
            "sandbox-prepared-rootfs-ext4-umoci-v3:openshell-{}:image-account:{trusted_digest}",
            openshell_core::VERSION,
        )
    };
    assert_ne!(legacy_identity, identity);
    let legacy_path = image_cache_rootfs_image(root.path(), &legacy_identity);
    fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
    fs::write(&legacy_path, b"legacy unverified disk").unwrap();

    let client = client();
    let error = ensure_image(&driver, &registry.reference(None), &client, bootstrap)
        .await
        .unwrap_err();
    assert!(error.message().contains("Invalid digest"), "{error}");
    assert!(error.message().contains(&trusted_digest), "{error}");
    assert!(
        registry
            .requests()
            .iter()
            .all(|request| !request.contains("/blobs/"))
    );
    assert!(!image_cache_rootfs_image(root.path(), &identity).exists());

    // A subsequent consumer pins the trusted image. It must miss the cache,
    // fetch that manifest, and fail rather than receive the replacement disk.
    let error = ensure_image(
        &driver,
        &registry.reference(Some(&trusted_digest)),
        &client,
        bootstrap,
    )
    .await
    .unwrap_err();
    assert!(error.message().contains("Invalid digest"), "{error}");
    assert!(!image_cache_rootfs_image(root.path(), &identity).exists());
    assert_eq!(fs::read(legacy_path).unwrap(), b"legacy unverified disk");
}

#[tokio::test]
async fn prepared_registry_cache_rejects_manifest_identity_mismatch() {
    rejects_unbound_manifest(false).await;
}

#[tokio::test]
async fn bootstrap_registry_cache_rejects_manifest_identity_mismatch() {
    rejects_unbound_manifest(true).await;
}

async fn accepts_sha512_pin(bootstrap: bool) {
    let trusted = manifest("trusted");
    for is_index in [false, true] {
        let top = if is_index {
            index(&trusted)
        } else {
            trusted.clone()
        };
        let digest = format!("sha512:{:x}", sha2::Sha512::digest(&top));
        // Canonical SHA-256 response headers are valid for a SHA-512 request.
        // The complete pin must still be checked, including for an index.
        let registry = Registry::start(
            sha256(&top),
            HashMap::from([(digest.clone(), top), (sha256(&trusted), trusted.clone())]),
            None,
            false,
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let driver = driver(root.path());
        let error = ensure_image(
            &driver,
            &registry.reference(Some(&digest)),
            &client(),
            bootstrap,
        )
        .await
        .unwrap_err();
        // Reaching the deliberate blob 404 proves real cache staging and
        // manifest verification succeeded without requiring a VM or formatter.
        let expected = if bootstrap {
            "failed to download layer"
        } else {
            "failed to download config"
        };
        assert!(error.message().contains(expected), "{error}");
        assert!(error.message().contains("404 Not Found"), "{error}");
        let requests = registry.requests();
        assert!(requests.contains(&format!("GET /v2/test/image/manifests/{digest}")));
        assert!(!requests.iter().any(|request| request.starts_with("HEAD ")));
        if is_index {
            assert!(requests.contains(&format!(
                "GET /v2/test/image/manifests/{}",
                sha256(&trusted)
            )));
        }
        assert!(requests.contains(&format!("GET /v2/test/image/blobs/{}", sha256(b"trusted"))));
    }
}

#[tokio::test]
async fn bootstrap_registry_cache_accepts_sha512_pins_and_canonical_sha256_headers() {
    accepts_sha512_pin(true).await;
}

#[tokio::test]
async fn prepared_registry_cache_accepts_sha512_pins_and_canonical_sha256_headers() {
    accepts_sha512_pin(false).await;
}

#[tokio::test]
async fn registry_pulls_pin_single_and_index_manifests_across_tag_changes_and_retries() {
    let trusted = manifest("trusted");
    let replacement = manifest("replacement");
    for is_index in [false, true] {
        for caller_pinned in [false, true] {
            let top = if is_index {
                index(&trusted)
            } else {
                trusted.clone()
            };
            let top_digest = sha256(&top);
            let registry = Registry::start(
                top_digest.clone(),
                HashMap::from([
                    ("latest".to_string(), replacement.clone()),
                    (top_digest.clone(), top),
                    (sha256(&trusted), trusted.clone()),
                ]),
                None,
                true,
            )
            .await;
            let client = client();
            let reference = parse_registry_reference(
                &registry.reference(caller_pinned.then_some(top_digest.as_str())),
            )
            .unwrap();
            let (reference, identity) =
                pin_registry_reference(&client, &reference, &RegistryAuth::Anonymous)
                    .await
                    .unwrap();
            let (pulled, platform_digest) =
                retry_registry_request_with_delay("test manifest", Duration::ZERO, || {
                    client.pull_image_manifest(&reference, &RegistryAuth::Anonymous)
                })
                .await
                .unwrap();
            assert_eq!(identity, top_digest);
            assert_eq!(platform_digest, sha256(&trusted));
            assert_eq!(pulled.config.digest, sha256(b"trusted"));
            let requests = registry.requests();
            assert!(
                !requests
                    .iter()
                    .any(|request| request == "GET /v2/test/image/manifests/latest")
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.starts_with("HEAD "))
                    .count(),
                usize::from(!caller_pinned)
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(
                        |request| *request == &format!("GET /v2/test/image/manifests/{top_digest}")
                    )
                    .count(),
                2
            );
        }
    }
}

#[tokio::test]
async fn registry_pulls_reject_changed_index_children_and_forged_get_headers() {
    let trusted = manifest("trusted");
    let replacement = manifest("replacement");
    for is_index in [false, true] {
        let top = if is_index {
            index(&trusted)
        } else {
            trusted.clone()
        };
        let digest = sha256(&top);
        let registry = Registry::start(
            digest.clone(),
            HashMap::from([
                (digest.clone(), top),
                (sha256(&trusted), replacement.clone()),
            ]),
            // Single manifest: even a forged GET header must not make the
            // replacement valid. Index: the child's own valid header differs.
            (!is_index).then(|| digest.clone()),
            false,
        )
        .await;
        let client = client();
        let reference = parse_registry_reference(&registry.reference(Some(&digest))).unwrap();
        let (reference, _) = pin_registry_reference(&client, &reference, &RegistryAuth::Anonymous)
            .await
            .unwrap();
        let error = client
            .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Invalid digest"), "{error}");
    }
}

#[tokio::test]
async fn registry_cache_preserves_caller_digest_when_head_uses_another_algorithm() {
    let trusted = manifest("trusted");
    let digest = sha256(&trusted);
    let registry = Registry::start(
        format!("sha512:{:x}", sha2::Sha512::digest(b"replacement")),
        HashMap::new(),
        None,
        false,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let driver = driver(root.path());
    let client = client();
    for bootstrap in [false, true] {
        let identity = if bootstrap {
            bootstrap_image_cache_identity(&digest)
        } else {
            prepared_image_cache_identity(&digest, &driver.config)
        };
        let path = image_cache_rootfs_image(root.path(), &identity);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"verified cached disk").unwrap();
        assert_eq!(
            ensure_image(
                &driver,
                &registry.reference(Some(&digest)),
                &client,
                bootstrap
            )
            .await
            .unwrap(),
            identity,
        );
        assert_eq!(fs::read(path).unwrap(), b"verified cached disk");
    }
    assert!(
        registry
            .requests()
            .iter()
            .all(|request| request == "GET /v2/")
    );
}
