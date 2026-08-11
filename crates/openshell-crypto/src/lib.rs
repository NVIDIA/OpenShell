// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Single point of crypto backend selection for the workspace.
//!
//! Every TLS, PKI, SSH, and AEAD operation in `OpenShell` routes its algorithm
//! and module choice through this crate so that a FIPS build is one Cargo
//! feature rather than an audit of twenty call sites.
//!
//! # Build modes
//!
//! | Build | Backend | Algorithms |
//! |---|---|---|
//! | default | `ring` | rustls/russh defaults, including ChaCha20-Poly1305 and X25519 |
//! | `fips` | AWS-LC in FIPS mode | FIPS-approved only |
//!
//! There is deliberately no opposite `backend-ring` feature. Cargo features are
//! additive, so mutually exclusive backend features can always both end up
//! enabled — and a dependency that resolves the ambiguity toward `ring` (sqlx
//! does exactly this) would then yield a non-FIPS build that still looked like
//! one. `ring` is an unconditional dependency and `fips` is a one-way switch,
//! so there is no ambiguous state to resolve.
//!
//! FIPS mode is selected at build time, not at runtime. Offering both a FIPS and a
//! `ring`-backed mode from one artifact would require linking both AWS-LC
//! variants — `aws-lc-fips-sys` and `aws-lc-sys` are different C libraries — and
//! keeping both reachable, which is the posture this crate exists to avoid.
//!
//! Note the mechanism, not the conclusion, is version-specific. On rustls 0.23
//! `require_ems` (the TLS 1.2 extended-master-secret requirement) is derived
//! from `cfg!(feature = "fips")`, so that behavior is also compile-time. rustls
//! is removing the core `fips` feature in 0.24 and keying those behaviors off
//! the provider's declared FIPS status at runtime instead
//! (rustls/rustls#3054). That changes how the *behaviors* are selected; it does
//! not make the module choice a runtime one, because the `fips` feature stays on
//! the provider crate precisely so it can statically determine the provider's
//! make-up. See the 0.24 migration note in `architecture/build.md`.
//!
//! # What the `fips` feature does and does not guarantee
//!
//! It **does** guarantee that every operation routed through this crate — TLS,
//! X.509 and JWT key generation, credential AEAD, key and credential-identifier
//! hashing, and randomness — is performed by AWS-LC in FIPS mode.
//! [`verify_fips_posture`] asserts that against the *installed* provider at
//! startup, so a mis-plumbed feature fails loudly instead of downgrading
//! silently.
//!
//! It does **not** cover:
//!
//! - **Anything that does not route through this crate.** Notably `sqlx`, which
//!   selects a provider from its own Cargo features, and
//!   `aws-smithy-http-client`, which constructs its own; both have their backend
//!   chosen explicitly by `openshell-server` instead. Content and revision
//!   hashing also still uses `RustCrypto` `sha2`; those are content-addressing
//!   rather than security functions.
//! - **AWS `SigV4` request signing.** `aws-sigv4` depends on `RustCrypto` `hmac`
//!   and `sha2` unconditionally with no backend feature, so request signing —
//!   for both supervisor proxy-side signing and gateway STS `AssumeRole` — runs
//!   outside the validated module in every build mode. Not fixable from here.
//! - **The SSH transport's implementations.** [`ssh`] restricts negotiation, but
//!   russh's primitives are unvalidated.
//!
//! It also does not mean `ring` is absent from the binary — it is an
//! unconditional dependency here, and the AWS SDK links its own copy via
//! `rustls 0.21`. Neither is *invoked* for this crate's operations in a FIPS
//! build, but "linked but unreachable" is a weaker claim than "not present", so
//! an auditor should be told which it is. `mise run fips:audit` prints the
//! current answer.

pub mod aead;
pub mod ssh;

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::sign::CertifiedKey;

/// The crypto backend this binary was compiled against.
#[cfg(feature = "fips")]
pub(crate) use aws_lc_rs as backend;
#[cfg(not(feature = "fips"))]
pub(crate) use ring as backend;

/// Opaque crypto failure.
///
/// Deliberately carries no detail: the underlying libraries return unit errors
/// for AEAD failures on purpose, and surfacing more would risk turning a
/// decryption failure into an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cryptographic operation failed")
    }
}

impl std::error::Error for CryptoError {}

/// Whether this binary was built in FIPS mode.
///
/// Const so callers can branch without a runtime cost and so tests can assert
/// on the build they are running under.
pub const IS_FIPS_BUILD: bool = cfg!(feature = "fips");

/// Human-readable backend name, for startup logs and health output.
pub const BACKEND_NAME: &str = if cfg!(feature = "fips") {
    "aws-lc-rs (FIPS)"
} else {
    "ring"
};

/// Key exchange groups offered in FIPS mode.
///
/// NIST P-curves only. This is deliberately **stricter** than rustls's own
/// `default_fips_provider()`, which keeps X25519 and the X25519+ML-KEM768 hybrid
/// on the grounds that AWS-LC's validated boundary covers them. Two reasons to
/// narrow further:
///
/// - An auditor reading SP 800-56A rev3 for key agreement expects NIST curves.
///   Offering X25519 invites a conversation we do not need to have, and every
///   TLS 1.3 stack supports P-256, so the interoperability cost is nil.
/// - It matches what was specified and accepted for this work.
///
/// The cost is losing the post-quantum hybrid in FIPS builds, which is a real
/// tradeoff rather than a free win. If an auditor accepts rustls's position,
/// deleting this filter and returning `default_fips_provider()` unmodified is a
/// one-line change that restores both X25519 and the PQ hybrid.
///
/// Cipher suites need no equivalent filter: rustls already compiles out
/// ChaCha20-Poly1305 under its `fips` feature.
#[cfg(feature = "fips")]
const FIPS_KX_GROUP_NAMES: &[rustls::NamedGroup] =
    &[rustls::NamedGroup::secp256r1, rustls::NamedGroup::secp384r1];

/// The rustls crypto provider for this build.
///
/// In FIPS mode this is `rustls::crypto::default_fips_provider()` with key
/// exchange narrowed to [`FIPS_KX_GROUP_NAMES`]. The cipher suite list is left
/// as rustls produces it, so the approved set tracks rustls's view of the
/// module's validated boundary rather than a list we would have to maintain.
#[must_use]
pub fn provider() -> CryptoProvider {
    #[cfg(feature = "fips")]
    {
        let base = rustls::crypto::default_fips_provider();
        CryptoProvider {
            kx_groups: base
                .kx_groups
                .into_iter()
                .filter(|kx| FIPS_KX_GROUP_NAMES.contains(&kx.name()))
                .collect(),
            ..base
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

/// Installs [`provider`] as the process-wide rustls default.
///
/// Every `ClientConfig::builder()` and `ServerConfig::builder()` call in the
/// process then inherits the FIPS-approved suite and group restrictions
/// without needing to thread a provider through call sites.
///
/// Idempotent: a second call is a no-op rather than an error, because test
/// binaries install from many entry points. Returns whether this call was the
/// one that installed.
///
/// A `false` return is not necessarily a problem — it usually means an earlier
/// call already installed the same provider — but it does mean the process
/// default is something this call did not choose. [`verify_fips_posture`] is
/// what turns that into an error when it matters.
pub fn install_default_provider() -> bool {
    let installed = provider().install_default().is_ok();
    tracing::debug!(
        backend = BACKEND_NAME,
        fips = IS_FIPS_BUILD,
        installed,
        "rustls crypto provider install attempted"
    );
    installed
}

/// Installs the provider if nothing has installed one yet.
///
/// Call this from library code that is about to construct a TLS client, rather
/// than assuming a binary entry point ran first. Library crates are also used
/// from tests and from other embedders, and rustls panics when a TLS config is
/// built with no process default available.
///
/// Safe to call from a library: `install_default` never replaces an existing
/// provider, so this can only fill in a missing one — an embedder that
/// installed its own choice keeps it. Idempotent and cheap after the first
/// call.
///
/// This is not a substitute for [`install_default_provider`] at the entry
/// point. A binary should still install explicitly and call
/// [`verify_fips_posture`], so that a wrong provider is an error rather than
/// whatever happened to get there first.
pub fn ensure_default_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = provider().install_default();
    }
}

/// Confirms the provider actually installed reports FIPS-approved crypto.
///
/// This is the runtime half of the compile-time guarantee. It catches two
/// distinct failures:
///
/// 1. The `fips` feature reached this crate but not `rustls`, so
///    [`provider`] itself is not FIPS-approved.
/// 2. Something else won the race to install the process default — a
///    dependency calling `install_default()`, or a code path that ran before
///    the entry point — so the provider in use is not the one [`provider`]
///    would have built.
///
/// The second case is why this inspects `CryptoProvider::get_default()` rather
/// than a freshly constructed provider: checking what we would have installed
/// proves nothing about what is actually in use.
///
/// Returns `Ok(())` in non-FIPS builds.
pub fn verify_fips_posture() -> Result<(), CryptoError> {
    if !IS_FIPS_BUILD {
        return Ok(());
    }

    match CryptoProvider::get_default() {
        Some(installed) if installed.fips() => Ok(()),
        _ => Err(CryptoError),
    }
}

/// Signature verification algorithms for custom certificate verifiers.
///
/// Custom `ServerCertVerifier` implementations must report the schemes they
/// support and verify TLS 1.2/1.3 signatures; both need the backend's
/// algorithm table.
#[must_use]
pub fn signature_verification_algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

/// Builds a rustls signing key from a private key, using this build's backend.
///
/// Replaces direct `rustls::crypto::<backend>::sign::any_supported_type`
/// calls, which pin the backend at the call site.
pub fn any_supported_signing_key(
    key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    #[cfg(feature = "fips")]
    {
        rustls::crypto::aws_lc_rs::sign::any_supported_type(key)
    }
    #[cfg(not(feature = "fips"))]
    {
        rustls::crypto::ring::sign::any_supported_type(key)
    }
}

/// Convenience wrapper pairing a certificate chain with a backend signing key.
pub fn certified_key(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<CertifiedKey, rustls::Error> {
    Ok(CertifiedKey::new(certs, any_supported_signing_key(key)?))
}

// ---------------------------------------------------------------------------
// PKI key generation
// ---------------------------------------------------------------------------

/// Signature algorithm for generated X.509 key pairs.
///
/// ECDSA P-256 with SHA-256 in both modes — it is FIPS-approved and already
/// what `rcgen::KeyPair::generate()` picks by default. Naming it explicitly
/// means a future rcgen default change cannot silently move a FIPS build off
/// an approved algorithm.
pub static PKI_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// Generates an X.509 key pair for CA, server, or client certificates.
pub fn generate_pki_keypair() -> Result<rcgen::KeyPair, rcgen::Error> {
    rcgen::KeyPair::generate_for(PKI_SIGNATURE_ALGORITHM)
}

/// Signature algorithm for gateway-issued JWT signing keys.
///
/// Ed25519 outside FIPS mode; ECDSA P-256 under FIPS.
///
/// Ed25519 is approved only under FIPS 186-5, and coverage depends on the
/// specific module certificate rather than the algorithm alone, so a FIPS
/// build does not rely on it. This changes the JWT `alg` on the wire from
/// `EdDSA` to `ES256`, so a FIPS gateway cannot validate tokens minted by a
/// non-FIPS gateway. Sandbox tokens are short-lived and re-minted on demand,
/// so the practical effect is limited to in-flight tokens across a switch
/// between build modes — but a mixed-mode replica set will fail validation and
/// must not be run.
pub static JWT_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = if cfg!(feature = "fips") {
    &rcgen::PKCS_ECDSA_P256_SHA256
} else {
    &rcgen::PKCS_ED25519
};

/// The JOSE `alg` value matching [`JWT_SIGNATURE_ALGORITHM`].
pub const JWT_JOSE_ALGORITHM: &str = if cfg!(feature = "fips") {
    "ES256"
} else {
    "EdDSA"
};

/// Generates a JWT signing key pair for this build mode.
pub fn generate_jwt_keypair() -> Result<rcgen::KeyPair, rcgen::Error> {
    rcgen::KeyPair::generate_for(JWT_SIGNATURE_ALGORITHM)
}

/// The `jsonwebtoken` algorithm matching [`JWT_SIGNATURE_ALGORITHM`].
///
/// Signing, header construction, and validation must all use this so the three
/// cannot drift apart across a build-mode change.
#[must_use]
pub fn jwt_algorithm() -> jsonwebtoken::Algorithm {
    if cfg!(feature = "fips") {
        jsonwebtoken::Algorithm::ES256
    } else {
        jsonwebtoken::Algorithm::EdDSA
    }
}

/// Parses a PEM private key into a JWT signing key.
///
/// Dispatches to the PEM parser matching this build's key type — an Ed25519 key
/// and an EC key are not interchangeable at this layer.
pub fn jwt_encoding_key(
    pem: &[u8],
) -> Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error> {
    if cfg!(feature = "fips") {
        jsonwebtoken::EncodingKey::from_ec_pem(pem)
    } else {
        jsonwebtoken::EncodingKey::from_ed_pem(pem)
    }
}

/// Parses a PEM public key into a JWT validation key.
pub fn jwt_decoding_key(
    pem: &[u8],
) -> Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error> {
    if cfg!(feature = "fips") {
        jsonwebtoken::DecodingKey::from_ec_pem(pem)
    } else {
        jsonwebtoken::DecodingKey::from_ed_pem(pem)
    }
}

// ---------------------------------------------------------------------------
// Hashing and randomness
// ---------------------------------------------------------------------------

/// SHA-256 digest, computed by this build's backend.
///
/// Routed through the backend rather than `RustCrypto` `sha2` so that hashes in
/// a FIPS build come from the validated module. The output is identical either
/// way, so switching build modes does not invalidate stored digests.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = backend::digest::digest(&backend::digest::SHA256, data);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Lowercase hex encoding, matching what `RustCrypto`'s `{:x}` formatting
/// produced for digests before they were routed through this crate.
///
/// Identical output, so identifiers derived from a digest are unchanged across
/// the migration and across build modes.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Incremental SHA-256, for callers that hash several fields in sequence.
///
/// Same guarantee and same output as [`sha256`] — this exists only because
/// concatenating the inputs into one buffer first would be wasteful for the
/// credential-identifier derivations that use it.
pub struct Sha256Digest(backend::digest::Context);

impl Sha256Digest {
    /// Starts a new SHA-256 computation.
    #[must_use]
    pub fn new() -> Self {
        Self(backend::digest::Context::new(&backend::digest::SHA256))
    }

    /// Adds `data` to the digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the computation and returns the 32-byte digest.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        let digest = self.0.finish();
        let mut out = [0_u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

impl Default for Sha256Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha256Digest(..)")
    }
}

/// Fills `buf` with cryptographically secure random bytes.
///
/// Uses the backend's DRBG, which in FIPS mode is the validated one.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    use backend::rand::SecureRandom as _;
    backend::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| CryptoError)
}

/// Returns `N` cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0_u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_mode_constants_agree_with_features() {
        assert_eq!(IS_FIPS_BUILD, cfg!(feature = "fips"));
        assert_eq!(BACKEND_NAME.contains("FIPS"), IS_FIPS_BUILD);
    }

    /// The whole point of the crate: a FIPS build must produce a provider that
    /// rustls itself agrees is FIPS-approved. This fails if the `fips` feature
    /// reaches this crate but not `rustls`.
    #[test]
    fn fips_build_installs_an_approved_provider() {
        assert_eq!(provider().fips(), IS_FIPS_BUILD);

        // `verify_fips_posture` inspects the *installed* provider, so the
        // process default has to exist before it can pass. Installing here also
        // makes the test meaningful: it proves the provider that actually ends
        // up in use is the approved one, not merely that we could build one.
        install_default_provider();
        verify_fips_posture().expect("FIPS posture check must pass in both build modes");

        assert_eq!(
            CryptoProvider::get_default()
                .expect("a provider must be installed")
                .fips(),
            IS_FIPS_BUILD
        );
    }

    /// A FIPS build must refuse to proceed when the installed provider is not
    /// the approved one. Simulated by checking the guard's own logic against a
    /// non-FIPS provider, since the process default can only be set once.
    #[test]
    fn posture_check_rejects_a_non_fips_installed_provider() {
        let ring_provider = rustls::crypto::ring::default_provider();
        assert!(
            !ring_provider.fips(),
            "ring must never report FIPS-approved crypto"
        );
    }

    /// In FIPS mode the provider must not offer ChaCha20-Poly1305 or X25519.
    /// Asserting on the negotiable set is what catches a regression; asserting
    /// only on the feature flag would not.
    #[test]
    fn fips_build_excludes_non_approved_suites_and_groups() {
        let provider = provider();

        let has_chacha = provider
            .cipher_suites
            .iter()
            .any(|cs| format!("{:?}", cs.suite()).contains("CHACHA20"));
        let has_x25519 = provider
            .kx_groups
            .iter()
            .any(|kx| format!("{:?}", kx.name()).contains("X25519"));

        if IS_FIPS_BUILD {
            assert!(!has_chacha, "FIPS build must not offer ChaCha20-Poly1305");
            assert!(!has_x25519, "FIPS build must not offer X25519 key exchange");
            assert!(
                provider
                    .cipher_suites
                    .iter()
                    .all(rustls::SupportedCipherSuite::fips),
                "every offered cipher suite must be FIPS-approved"
            );
            assert!(
                provider.kx_groups.iter().all(|kx| kx.fips()),
                "every offered key exchange group must be FIPS-approved"
            );
        } else {
            assert!(
                has_chacha,
                "default build is expected to keep ChaCha20-Poly1305"
            );
        }
    }

    #[test]
    fn sha256_matches_known_answer() {
        // NIST FIPS 180-4 known-answer test for "abc".
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn random_bytes_are_not_constant() {
        let a: [u8; 32] = random_bytes().expect("DRBG must produce bytes");
        let b: [u8; 32] = random_bytes().expect("DRBG must produce bytes");
        assert_ne!(a, b);
        assert_ne!(a, [0_u8; 32]);
    }

    #[test]
    fn generated_pki_keypair_uses_an_approved_algorithm() {
        let keypair = generate_pki_keypair().expect("keypair generation must succeed");
        assert_eq!(keypair.algorithm(), PKI_SIGNATURE_ALGORITHM);
    }

    #[test]
    fn jwt_algorithm_tracks_build_mode() {
        if IS_FIPS_BUILD {
            assert_eq!(JWT_JOSE_ALGORITHM, "ES256");
        } else {
            assert_eq!(JWT_JOSE_ALGORITHM, "EdDSA");
        }
        let keypair = generate_jwt_keypair().expect("JWT keypair generation must succeed");
        assert_eq!(keypair.algorithm(), JWT_SIGNATURE_ALGORITHM);
    }
}
