// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, Error, KeyIdMethod, KeyUsagePurpose,
};
use x509_parser::{der_parser::asn1_rs::Tag, extensions::ParsedExtension};

use super::KeyPair;

/// Read issuer metadata without enabling a parser-owned cryptographic backend.
///
/// This does not establish trust, verify the certificate signature, or check
/// that the key matches. Callers must validate their provisioned certificate and
/// key separately. Unsupported subject encodings are rejected rather than
/// silently changing the issuer name. The original certificate is not reissued.
pub fn issuer_from_der(der: &[u8], key: KeyPair) -> Result<rcgen::Issuer<'static, KeyPair>, Error> {
    let invalid = || Error::CouldNotParseCertificate;
    let (rest, cert) = x509_parser::parse_x509_certificate(der).map_err(|_| invalid())?;
    if !rest.is_empty() {
        return Err(invalid());
    }
    let mut name = DistinguishedName::new();
    for rdn in cert.subject().iter_rdn() {
        let mut attributes = rdn.iter();
        let attribute = attributes.next().ok_or_else(invalid)?;
        // rcgen represents each RDN as one attribute and each OID only once.
        if attributes.next().is_some() {
            return Err(invalid());
        }
        let oid: Vec<_> = attribute.attr_type().iter().ok_or_else(invalid)?.collect();
        let kind = DnType::from_oid(&oid);
        if name.get(&kind).is_some() {
            return Err(invalid());
        }
        let value = attribute.attr_value();
        let string = || std::str::from_utf8(value.data).map_err(|_| invalid());
        let value = match value.tag() {
            Tag::Utf8String => DnValue::Utf8String(string()?.to_owned()),
            Tag::PrintableString => DnValue::PrintableString(string()?.try_into()?),
            Tag::Ia5String => DnValue::Ia5String(string()?.try_into()?),
            Tag::T61String => DnValue::TeletexString(string()?.try_into()?),
            Tag::BmpString => {
                DnValue::BmpString(rcgen::string::BmpString::from_utf16be(value.data.to_vec())?)
            }
            Tag::UniversalString => DnValue::UniversalString(
                rcgen::string::UniversalString::from_utf32be(value.data.to_vec())?,
            ),
            _ => return Err(invalid()),
        };
        name.push(kind, value);
    }
    let mut usages = Vec::new();
    if let Some(extension) = cert.key_usage().map_err(|_| invalid())? {
        let usage = extension.value;
        for (present, purpose) in [
            (usage.digital_signature(), KeyUsagePurpose::DigitalSignature),
            (usage.non_repudiation(), KeyUsagePurpose::ContentCommitment),
            (usage.key_encipherment(), KeyUsagePurpose::KeyEncipherment),
            (usage.data_encipherment(), KeyUsagePurpose::DataEncipherment),
            (usage.key_agreement(), KeyUsagePurpose::KeyAgreement),
            (usage.key_cert_sign(), KeyUsagePurpose::KeyCertSign),
            (usage.crl_sign(), KeyUsagePurpose::CrlSign),
            (usage.encipher_only(), KeyUsagePurpose::EncipherOnly),
            (usage.decipher_only(), KeyUsagePurpose::DecipherOnly),
        ] {
            if present {
                usages.push(purpose);
            }
        }
    }
    let mut identifier = None;
    for extension in cert.extensions() {
        if extension.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
            if identifier.is_some() {
                return Err(invalid());
            }
            let ParsedExtension::SubjectKeyIdentifier(value) = extension.parsed_extension() else {
                return Err(invalid());
            };
            identifier = Some(value.0.to_vec());
        }
    }
    // Match our certificate-generation default, using the selected backend.
    let identifier = match identifier {
        Some(identifier) => identifier,
        None => {
            crate::sha256(cert.public_key().raw).map_err(|_| Error::RemoteKeyError)?[..20].to_vec()
        }
    };
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.key_usages = usages;
    params.key_identifier_method = KeyIdMethod::PreSpecified(identifier);
    Ok(rcgen::Issuer::new(params, key))
}
