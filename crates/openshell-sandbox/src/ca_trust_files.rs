// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The supervisor's public CA certificate and combined trust bundle, cached
//! as sealed in-memory files.
//!
//! The runtime installs both as real read-only files beneath
//! `SUPERVISOR_CA_RUNTIME_DIR` before the workload starts, and the child
//! Landlock grants keep that directory readable. Every workload open already
//! notifies the broker, and a plain read-only `open` or `openat` of exactly
//! one of the two canonical paths is answered from this cache with the same
//! immutable, sealed delivery a provider file receives. Every other open of
//! those paths continues to the kernel, as it did before the cache existed.
//!
//! The installed files remain the compatibility source: `stat` and other
//! metadata checks, `O_PATH` and `O_DIRECTORY` opens, `openat2`, relative
//! opens, and aliases such as a path through `..` all reach them. The
//! standard TLS environment variables and the image's system trust store are
//! untouched, and no private key is ever here: both files are public
//! material the supervisor already sends the workload.
//!
//! The two files are one generation. A publication prepares both before it
//! replaces the pair, so a failed update leaves the previous complete pair in
//! place, and a publication of the bytes already published keeps the files
//! every earlier open used. A start without CA material clears the pair.

use std::io;
use std::sync::{Arc, RwLock};

use rustix::fs::Mode;

use openshell_sandbox_backend::boundary_protocol::MAX_CONTROL_FRAME_BYTES;

use crate::linux::sealed_file::{OwnDescriptors, SealedFile};

/// File name of the supervisor's public CA certificate.
pub const CA_CERT_FILE_NAME: &str = "ca.crt";
/// File name of the combined trust bundle: the system CAs plus the
/// supervisor CA.
pub const CA_BUNDLE_FILE_NAME: &str = "ca-bundle.crt";
/// Canonical workload path of the supervisor CA certificate.
pub const CA_CERT_PATH: &str = "/run/openshell-supervisor-ca/material/ca.crt";
/// Canonical workload path of the combined trust bundle.
pub const CA_BUNDLE_PATH: &str = "/run/openshell-supervisor-ca/material/ca-bundle.crt";

/// The most either file may hold.
///
/// A system trust bundle is commonly several hundred KiB, far beyond the
/// per-file bound of provider files, so the CA files have their own. The
/// bound equals the control frame that carries both files to the runtime: no
/// start request that the protocol admits is refused here, and no file
/// larger than a frame can be published.
pub const MAX_TRUST_FILE_BYTES: usize = MAX_CONTROL_FRAME_BYTES;

/// The mode the injected files report, the same as the installed files.
const FILE_MODE: Mode = Mode::from_bits_truncate(0o444);

/// Refuse a pair that is not a complete, consistent supervisor trust set.
///
/// Both files must be present and within bounds, and the bundle must contain
/// the certificate: the supervisor builds the bundle from the system CAs and
/// its own certificate, so a bundle without it would trust every upstream
/// except the interception endpoint the workload must reach.
pub fn validate_pair(ca_cert: &[u8], ca_bundle: &[u8]) -> io::Result<()> {
    let invalid = |message: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    if ca_cert.is_empty() || ca_bundle.is_empty() {
        return invalid("supervisor CA certificate and bundle must not be empty");
    }
    if ca_cert.len() > MAX_TRUST_FILE_BYTES || ca_bundle.len() > MAX_TRUST_FILE_BYTES {
        return invalid("supervisor CA certificate or bundle exceeds the trust file bound");
    }
    let certificate = ca_cert.trim_ascii();
    if certificate.is_empty()
        || !ca_bundle
            .windows(certificate.len())
            .any(|window| window == certificate)
    {
        return invalid("supervisor CA bundle does not contain the supervisor CA certificate");
    }
    Ok(())
}

/// One published trust set: the bytes of both files and their backing.
struct TrustPair {
    cert: Vec<u8>,
    bundle: Vec<u8>,
    cert_file: SealedFile,
    bundle_file: SealedFile,
}

/// The published supervisor trust files, replaced only as a pair.
#[derive(Default)]
pub struct CaTrustFiles {
    current: RwLock<Option<Arc<TrustPair>>>,
}

impl CaTrustFiles {
    fn current(&self) -> Option<Arc<TrustPair>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Publish `ca_cert` and `ca_bundle` as the trust pair, or leave the
    /// published pair untouched.
    ///
    /// The same bytes as the published pair publish nothing new, so a start
    /// retried after a failed launch keeps the files earlier opens used.
    pub(crate) fn publish(&self, ca_cert: &[u8], ca_bundle: &[u8]) -> io::Result<()> {
        validate_pair(ca_cert, ca_bundle)?;
        if self
            .current()
            .is_some_and(|pair| pair.cert == ca_cert && pair.bundle == ca_bundle)
        {
            return Ok(());
        }
        let descriptors = OwnDescriptors::shared()?;
        let prepared = Arc::new(TrustPair {
            cert_file: SealedFile::create("openshell-ca", FILE_MODE, ca_cert, &descriptors)?,
            bundle_file: SealedFile::create(
                "openshell-ca-bundle",
                FILE_MODE,
                ca_bundle,
                &descriptors,
            )?,
            cert: ca_cert.to_vec(),
            bundle: ca_bundle.to_vec(),
        });
        let replaced = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(prepared);
        drop(replaced);
        Ok(())
    }

    /// Forget the published pair, if any. Descriptors already injected keep
    /// the files they opened; later opens of the canonical paths continue to
    /// the kernel.
    pub(crate) fn clear(&self) {
        let replaced = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(replaced);
    }

    /// The file serving exactly `path`, if it is a canonical trust path and a
    /// pair is published. Any other path, including an alias of these, is
    /// not served here.
    pub(crate) fn lookup(&self, path: &str) -> Option<TrustFile> {
        let pair = self.current()?;
        match path {
            CA_CERT_PATH => Some(TrustFile {
                pair,
                which: Which::Cert,
            }),
            CA_BUNDLE_PATH => Some(TrustFile {
                pair,
                which: Which::Bundle,
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Which {
    Cert,
    Bundle,
}

/// One trust file of a published pair, held for the duration of an open so
/// a concurrent publication cannot close its backing.
pub struct TrustFile {
    pair: Arc<TrustPair>,
    which: Which,
}

impl TrustFile {
    pub(crate) fn backing(&self) -> &SealedFile {
        match self.which {
            Which::Cert => &self.pair.cert_file,
            Which::Bundle => &self.pair.bundle_file,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CA_BUNDLE_PATH, CA_CERT_PATH, CaTrustFiles, MAX_TRUST_FILE_BYTES, validate_pair};
    use std::fs::File;
    use std::io::{self, Read as _};
    use std::os::unix::fs::MetadataExt as _;

    const CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\nsupervisor\n-----END CERTIFICATE-----\n";

    fn bundle_with(system_bytes: usize) -> Vec<u8> {
        let mut bundle = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        bundle.extend(std::iter::repeat_n(b'A', system_bytes));
        bundle.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
        bundle.extend_from_slice(CERT);
        bundle
    }

    fn open(files: &CaTrustFiles, path: &str) -> Option<File> {
        Some(File::from(files.lookup(path)?.backing().open().unwrap()))
    }

    fn read(files: &CaTrustFiles, path: &str) -> Option<(Vec<u8>, (u64, u64))> {
        let file = open(files, path)?;
        let metadata = file.metadata().unwrap();
        let mut content = Vec::new();
        (&file).read_to_end(&mut content).unwrap();
        Some((content, (metadata.dev(), metadata.ino())))
    }

    #[test]
    fn a_pair_must_be_complete_consistent_and_bounded() {
        assert!(validate_pair(CERT, &bundle_with(16)).is_ok());
        assert!(validate_pair(CERT, &bundle_with(300 * 1024)).is_ok());
        for (cert, bundle) in [
            (
                CERT,
                b"-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----\n".as_slice(),
            ),
            (b"".as_slice(), CERT),
            (CERT, b"".as_slice()),
            (b"   \n".as_slice(), CERT),
        ] {
            assert_eq!(
                validate_pair(cert, bundle).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let oversized = bundle_with(MAX_TRUST_FILE_BYTES);
        assert_eq!(
            validate_pair(CERT, &oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_pair_is_published_whole_and_replaced_whole_or_not_at_all() {
        let files = CaTrustFiles::default();
        assert!(files.lookup(CA_CERT_PATH).is_none());
        assert!(files.lookup(CA_BUNDLE_PATH).is_none());

        let first_bundle = bundle_with(100 * 1024);
        files.publish(CERT, &first_bundle).unwrap();
        let (cert, cert_identity) = read(&files, CA_CERT_PATH).unwrap();
        let (bundle, bundle_identity) = read(&files, CA_BUNDLE_PATH).unwrap();
        assert_eq!(cert, CERT);
        assert_eq!(bundle, first_bundle);
        assert_ne!(cert_identity, bundle_identity);
        let mode = open(&files, CA_CERT_PATH)
            .unwrap()
            .metadata()
            .unwrap()
            .mode();
        assert_eq!(mode & 0o7777, 0o444);

        // The same bytes, or a refused pair, keep both files.
        files.publish(CERT, &first_bundle).unwrap();
        let error = files.publish(CERT, b"unrelated").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(read(&files, CA_CERT_PATH).unwrap().1, cert_identity);
        assert_eq!(read(&files, CA_BUNDLE_PATH).unwrap().1, bundle_identity);

        // A changed bundle replaces both files; a held descriptor keeps its own.
        let held = open(&files, CA_BUNDLE_PATH).unwrap();
        let second_bundle = bundle_with(32);
        files.publish(CERT, &second_bundle).unwrap();
        let (bundle, new_bundle_identity) = read(&files, CA_BUNDLE_PATH).unwrap();
        assert_eq!(bundle, second_bundle);
        assert_ne!(new_bundle_identity, bundle_identity);
        assert_ne!(read(&files, CA_CERT_PATH).unwrap().1, cert_identity);
        let mut old = Vec::new();
        (&held).read_to_end(&mut old).unwrap();
        assert_eq!(old, first_bundle);

        // Clearing forgets the pair for later opens only.
        let held_cert = open(&files, CA_CERT_PATH).unwrap();
        files.clear();
        assert!(files.lookup(CA_CERT_PATH).is_none());
        assert!(files.lookup(CA_BUNDLE_PATH).is_none());
        let mut after_clear = Vec::new();
        (&held_cert).read_to_end(&mut after_clear).unwrap();
        assert_eq!(after_clear, CERT);
        files.clear();
        files.publish(CERT, &second_bundle).unwrap();
        assert_eq!(read(&files, CA_BUNDLE_PATH).unwrap().0, second_bundle);

        for alias in [
            "/run/openshell-supervisor-ca/material/../material/ca.crt",
            "/run/openshell-supervisor-ca/material/ca.crt/",
            "/run/openshell-supervisor-ca/ca.crt",
            "/run/openshell-supervisor-ca/material",
            "ca.crt",
        ] {
            assert!(files.lookup(alias).is_none(), "{alias}");
        }
    }
}
