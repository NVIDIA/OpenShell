// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH algorithm selection for the gateway-to-sandbox transport.
//!
//! # Scope of the FIPS guarantee here
//!
//! In FIPS mode this narrows *negotiation* to FIPS-approved algorithms. It does
//! **not** make the SSH transport FIPS-validated: russh implements its own
//! crypto via `ed25519-dalek`, `p256`, and `RustCrypto` AES, none of which are
//! validated modules, and none of which this crate can substitute.
//!
//! That gap is accepted deliberately, and the reasoning is worth recording
//! because it is the load-bearing assumption of the whole phase:
//!
//! - This transport runs inside the gateway's mTLS boundary, so it is
//!   defense-in-depth rather than the primary trust boundary.
//! - The SSH layer performs no authentication of its own — `auth_none` and
//!   `auth_publickey` both accept unconditionally, with trust established by
//!   unix-socket peer credentials.
//!
//! Closing the gap requires either an aws-lc-rs backend upstream in russh or
//! replacing the embedded server with OpenSSH. Both are out of scope here.

use std::borrow::Cow;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use russh::{Preferred, cipher, kex, mac};

/// Host key algorithm for the sandbox SSH server.
///
/// Ed25519 outside FIPS mode. Under FIPS, ECDSA P-256: Ed25519's approval
/// depends on the module certificate covering FIPS 186-5 `EdDSA`, which is not a
/// property we can assert for russh's implementation.
///
/// This changes the host key fingerprint between build modes. Sandboxes are
/// ephemeral and the host key is generated per sandbox, so there is no
/// persistent known-hosts entry to invalidate.
#[must_use]
pub fn host_key_algorithm() -> Algorithm {
    if cfg!(feature = "fips") {
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }
    } else {
        Algorithm::Ed25519
    }
}

/// Generates a host key for the sandbox SSH server.
///
/// The RNG is `rand::rng()` (a userspace `ChaCha12` construction), which is not a
/// validated DRBG. That is deliberate rather than overlooked: `ssh-key` performs
/// the ECDSA key derivation itself in unvalidated code, so substituting the
/// entropy source would not move this operation inside a validated boundary. It
/// is listed with the rest of the SSH gap in the module docs above.
///
/// Swapping in the backend DRBG is also not currently practical — `ssh-key`
/// requires `rand_core` 0.10 traits while the rest of the workspace is on 0.9,
/// so the adapter would pin a version relationship for no security gain.
pub fn generate_host_key() -> Result<PrivateKey, russh::keys::ssh_key::Error> {
    let mut rng = rand::rng();
    PrivateKey::random(&mut rng, host_key_algorithm())
}

/// FIPS-approved key exchange algorithms, most preferred first.
///
/// The `EXTENSION_*` entries are negotiation markers, not key agreement
/// algorithms, and must be retained: dropping the strict-kex markers would
/// disable the Terrapin (CVE-2023-48795) mitigation.
///
/// Diffie-Hellman group exchange (`diffie-hellman-group-exchange-sha256`) is
/// deliberately excluded — the group is server-chosen, so an approved
/// implementation cannot be asserted from the algorithm name alone.
const FIPS_KEX: &[kex::Name] = &[
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_G16_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// FIPS-approved host and public key algorithms. Ed25519 is absent.
const FIPS_KEY: &[Algorithm] = &[
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

/// FIPS-approved ciphers. ChaCha20-Poly1305 is absent; AES-GCM is preferred
/// over AES-CTR because it is authenticated.
const FIPS_CIPHER: &[cipher::Name] = &[
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_128_CTR,
];

/// FIPS-approved MACs. Encrypt-then-MAC variants first; no SHA-1.
const FIPS_MAC: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

/// Algorithm preferences for both SSH server and client configs.
///
/// Returns russh's defaults outside FIPS mode, so non-FIPS behavior is
/// unchanged.
#[must_use]
pub fn preferred() -> Preferred {
    if cfg!(feature = "fips") {
        Preferred {
            kex: Cow::Borrowed(FIPS_KEX),
            key: Cow::Borrowed(FIPS_KEY),
            cipher: Cow::Borrowed(FIPS_CIPHER),
            mac: Cow::Borrowed(FIPS_MAC),
            compression: Cow::Borrowed(&[russh::compression::NONE]),
        }
    } else {
        Preferred::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_algorithm_tracks_build_mode() {
        if cfg!(feature = "fips") {
            assert_eq!(
                host_key_algorithm(),
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256
                }
            );
        } else {
            assert_eq!(host_key_algorithm(), Algorithm::Ed25519);
        }
    }

    #[test]
    fn generated_host_key_matches_the_selected_algorithm() {
        let key = generate_host_key().expect("host key generation must succeed");
        assert_eq!(key.algorithm(), host_key_algorithm());
    }

    /// The assertion that matters: in FIPS mode the negotiable sets must not
    /// contain the non-approved algorithms. Checking the feature flag alone
    /// would not catch a regression in the lists above.
    #[test]
    fn fips_preferences_exclude_non_approved_algorithms() {
        let preferred = preferred();

        let kex: Vec<&str> = preferred.kex.iter().map(AsRef::as_ref).collect();
        let ciphers: Vec<&str> = preferred.cipher.iter().map(AsRef::as_ref).collect();
        let macs: Vec<&str> = preferred.mac.iter().map(AsRef::as_ref).collect();

        if cfg!(feature = "fips") {
            assert!(
                !kex.iter().any(|n| n.contains("curve25519")),
                "FIPS mode must not offer Curve25519 key exchange: {kex:?}"
            );
            assert!(
                !kex.iter().any(|n| n.contains("mlkem")),
                "FIPS mode must not offer ML-KEM hybrid key exchange: {kex:?}"
            );
            assert!(
                !ciphers.iter().any(|n| n.contains("chacha20")),
                "FIPS mode must not offer ChaCha20-Poly1305: {ciphers:?}"
            );
            assert!(
                !preferred.key.contains(&Algorithm::Ed25519),
                "FIPS mode must not offer Ed25519 host keys"
            );
            assert!(
                !macs.iter().any(|n| n.contains("sha1")),
                "FIPS mode must not offer HMAC-SHA1: {macs:?}"
            );
            assert!(
                ciphers.contains(&"aes256-gcm@openssh.com"),
                "AES-256-GCM must remain available or nothing can connect"
            );
            assert!(
                kex.contains(&"ecdh-sha2-nistp256"),
                "at least one approved kex must remain available"
            );
        } else {
            assert!(
                ciphers.iter().any(|n| n.contains("chacha20")),
                "default build is expected to keep russh's defaults"
            );
        }
    }

    /// Terrapin mitigation must survive the FIPS restriction.
    #[test]
    fn strict_kex_markers_are_retained() {
        let preferred = preferred();
        let kex: Vec<&str> = preferred.kex.iter().map(AsRef::as_ref).collect();
        assert!(
            kex.contains(&"kex-strict-c-v00@openssh.com"),
            "strict-kex client marker missing; Terrapin mitigation would be disabled: {kex:?}"
        );
        assert!(
            kex.contains(&"kex-strict-s-v00@openssh.com"),
            "strict-kex server marker missing; Terrapin mitigation would be disabled: {kex:?}"
        );
    }
}
