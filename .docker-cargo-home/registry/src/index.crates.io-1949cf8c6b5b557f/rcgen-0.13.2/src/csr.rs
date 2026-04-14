use std::hash::Hash;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::CertificateSigningRequestDer;

#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	key_pair::serialize_public_key_der, Certificate, CertificateParams, Error, Issuer, KeyPair,
	PublicKeyData, SignatureAlgorithm,
};
#[cfg(feature = "x509-parser")]
use crate::{DistinguishedName, SanType};

/// A public key, extracted from a CSR
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
	raw: Vec<u8>,
	alg: &'static SignatureAlgorithm,
}

impl PublicKey {
	/// The algorithm used to generate the public key and sign the CSR.
	pub fn algorithm(&self) -> &SignatureAlgorithm {
		self.alg
	}
}

impl PublicKeyData for PublicKey {
	fn der_bytes(&self) -> &[u8] {
		&self.raw
	}

	fn algorithm(&self) -> &SignatureAlgorithm {
		self.alg
	}
}

/// A certificate signing request (CSR) that can be encoded to PEM or DER.
pub struct CertificateSigningRequest {
	pub(crate) der: CertificateSigningRequestDer<'static>,
}

impl CertificateSigningRequest {
	/// Get the PEM-encoded bytes of the certificate signing request.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> Result<String, Error> {
		let p = Pem::new("CERTIFICATE REQUEST", &*self.der);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}

	/// Get the DER-encoded bytes of the certificate signing request.
	///
	/// [`CertificateSigningRequestDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`,
	/// so you can easily extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateSigningRequestDer<'static> {
		&self.der
	}
}

impl From<CertificateSigningRequest> for CertificateSigningRequestDer<'static> {
	fn from(csr: CertificateSigningRequest) -> Self {
		csr.der
	}
}

/// Parameters for a certificate signing request
pub struct CertificateSigningRequestParams {
	/// Parameters for the certificate to be signed.
	pub params: CertificateParams,
	/// Public key to include in the certificate signing request.
	pub public_key: PublicKey,
}

impl CertificateSigningRequestParams {
	/// Parse a certificate signing request from the ASCII PEM format
	///
	/// See [`from_der`](Self::from_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_pem(pem_str: &str) -> Result<Self, Error> {
		let csr = pem::parse(pem_str).or(Err(Error::CouldNotParseCertificationRequest))?;
		Self::from_der(&csr.contents().into())
	}

	/// Parse a certificate signing request from DER-encoded bytes
	///
	/// Currently, this only supports the `Subject Alternative Name` extension.
	/// On encountering other extensions, this function will return an error.
	///
	/// [`rustls_pemfile::csr()`] is often used to obtain a [`CertificateSigningRequestDer`] from
	/// PEM input. If you already have a byte slice containing DER, it can trivially be converted
	/// into [`CertificateSigningRequestDer`] using the [`Into`] trait.
	///
	/// [`rustls_pemfile::csr()`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.csr.html
	#[cfg(feature = "x509-parser")]
	pub fn from_der(csr: &CertificateSigningRequestDer<'_>) -> Result<Self, Error> {
		use crate::KeyUsagePurpose;
		use x509_parser::prelude::FromDer;

		let csr = x509_parser::certification_request::X509CertificationRequest::from_der(csr)
			.map_err(|_| Error::CouldNotParseCertificationRequest)?
			.1;
		csr.verify_signature().map_err(|_| Error::RingUnspecified)?;
		let alg_oid = csr
			.signature_algorithm
			.algorithm
			.iter()
			.ok_or(Error::CouldNotParseCertificationRequest)?
			.collect::<Vec<_>>();
		let alg = SignatureAlgorithm::from_oid(&alg_oid)?;

		let info = &csr.certification_request_info;
		let mut params = CertificateParams {
			distinguished_name: DistinguishedName::from_name(&info.subject)?,
			..CertificateParams::default()
		};
		let raw = info.subject_pki.subject_public_key.data.to_vec();

		if let Some(extensions) = csr.requested_extensions() {
			for ext in extensions {
				match ext {
					x509_parser::extensions::ParsedExtension::KeyUsage(key_usage) => {
						// This x509 parser stores flags in reversed bit BIT STRING order
						params.key_usages =
							KeyUsagePurpose::from_u16(key_usage.flags.reverse_bits());
					},
					x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
						for name in &san.general_names {
							params
								.subject_alt_names
								.push(SanType::try_from_general(name)?);
						}
					},
					x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
						if eku.any {
							params.insert_extended_key_usage(crate::ExtendedKeyUsagePurpose::Any);
						}
						if eku.server_auth {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::ServerAuth,
							);
						}
						if eku.client_auth {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::ClientAuth,
							);
						}
						if eku.code_signing {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::CodeSigning,
							);
						}
						if eku.email_protection {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::EmailProtection,
							);
						}
						if eku.time_stamping {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::TimeStamping,
							);
						}
						if eku.ocsp_signing {
							params.insert_extended_key_usage(
								crate::ExtendedKeyUsagePurpose::OcspSigning,
							);
						}
						if !eku.other.is_empty() {
							return Err(Error::UnsupportedExtension);
						}
					},
					_ => return Err(Error::UnsupportedExtension),
				}
			}
		}

		// Not yet handled:
		// * is_ca
		// * extended_key_usages
		// * name_constraints
		// and any other extensions.

		Ok(Self {
			params,
			public_key: PublicKey { alg, raw },
		})
	}

	/// Generate a new certificate based on the requested parameters, signed by the provided
	/// issuer.
	///
	/// The returned certificate will have its issuer field set to the subject of the provided
	/// `issuer`, and the authority key identifier extension will be populated using the subject
	/// public key of `issuer`. It will be signed by `issuer_key`.
	///
	/// Note that no validation of the `issuer` certificate is performed. Rcgen will not require
	/// the certificate to be a CA certificate, or have key usage extensions that allow signing.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn signed_by(
		self,
		issuer: &Certificate,
		issuer_key: &KeyPair,
	) -> Result<Certificate, Error> {
		let issuer = Issuer {
			distinguished_name: &issuer.params.distinguished_name,
			key_identifier_method: &issuer.params.key_identifier_method,
			key_usages: &issuer.params.key_usages,
			key_pair: issuer_key,
		};

		let der = self
			.params
			.serialize_der_with_signer(&self.public_key, issuer)?;
		let subject_public_key_info = yasna::construct_der(|writer| {
			serialize_public_key_der(&self.public_key, writer);
		});
		Ok(Certificate {
			params: self.params,
			subject_public_key_info,
			der,
		})
	}
}
