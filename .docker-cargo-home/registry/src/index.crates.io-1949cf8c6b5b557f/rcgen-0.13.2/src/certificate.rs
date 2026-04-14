use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::{CertificateDer, CertificateSigningRequestDer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use yasna::models::ObjectIdentifier;
use yasna::{DERWriter, Tag};

use crate::crl::CrlDistributionPoint;
use crate::csr::CertificateSigningRequest;
use crate::key_pair::{serialize_public_key_der, PublicKeyData};
#[cfg(feature = "crypto")]
use crate::ring_like::digest;
#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	oid, write_distinguished_name, write_dt_utc_or_generalized,
	write_x509_authority_key_identifier, write_x509_extension, DistinguishedName, Error, Issuer,
	KeyIdMethod, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};

/// An issued certificate together with the parameters used to generate it.
pub struct Certificate {
	pub(crate) params: CertificateParams,
	pub(crate) subject_public_key_info: Vec<u8>,
	pub(crate) der: CertificateDer<'static>,
}

impl Certificate {
	/// Returns the certificate parameters
	pub fn params(&self) -> &CertificateParams {
		&self.params
	}
	/// Calculates a subject key identifier for the certificate subject's public key.
	/// This key identifier is used in the SubjectKeyIdentifier X.509v3 extension.
	pub fn key_identifier(&self) -> Vec<u8> {
		self.params
			.key_identifier_method
			.derive(&self.subject_public_key_info)
	}
	/// Get the certificate in DER encoded format.
	///
	/// [`CertificateDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`, so you can easily
	/// extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateDer<'static> {
		&self.der
	}
	/// Get the certificate in PEM encoded format.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> String {
		pem::encode_config(&Pem::new("CERTIFICATE", self.der().to_vec()), ENCODE_CONFIG)
	}
}

impl From<Certificate> for CertificateDer<'static> {
	fn from(cert: Certificate) -> Self {
		cert.der
	}
}

/// Parameters used for certificate generation
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CertificateParams {
	pub not_before: OffsetDateTime,
	pub not_after: OffsetDateTime,
	pub serial_number: Option<SerialNumber>,
	pub subject_alt_names: Vec<SanType>,
	pub distinguished_name: DistinguishedName,
	pub is_ca: IsCa,
	pub key_usages: Vec<KeyUsagePurpose>,
	pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
	pub name_constraints: Option<NameConstraints>,
	/// An optional list of certificate revocation list (CRL) distribution points as described
	/// in RFC 5280 Section 4.2.1.13[^1]. Each distribution point contains one or more URIs where
	/// an up-to-date CRL with scope including this certificate can be retrieved.
	///
	/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
	pub crl_distribution_points: Vec<CrlDistributionPoint>,
	pub custom_extensions: Vec<CustomExtension>,
	/// If `true`, the 'Authority Key Identifier' extension will be added to the generated cert
	pub use_authority_key_identifier_extension: bool,
	/// Method to generate key identifiers from public keys
	///
	/// Defaults to a truncated SHA-256 digest. See [`KeyIdMethod`] for more information.
	pub key_identifier_method: KeyIdMethod,
}

impl Default for CertificateParams {
	fn default() -> Self {
		// not_before and not_after set to reasonably long dates
		let not_before = date_time_ymd(1975, 01, 01);
		let not_after = date_time_ymd(4096, 01, 01);
		let mut distinguished_name = DistinguishedName::new();
		distinguished_name.push(DnType::CommonName, "rcgen self signed cert");
		CertificateParams {
			not_before,
			not_after,
			serial_number: None,
			subject_alt_names: Vec::new(),
			distinguished_name,
			is_ca: IsCa::NoCa,
			key_usages: Vec::new(),
			extended_key_usages: Vec::new(),
			name_constraints: None,
			crl_distribution_points: Vec::new(),
			custom_extensions: Vec::new(),
			use_authority_key_identifier_extension: false,
			#[cfg(feature = "crypto")]
			key_identifier_method: KeyIdMethod::Sha256,
			#[cfg(not(feature = "crypto"))]
			key_identifier_method: KeyIdMethod::PreSpecified(Vec::new()),
		}
	}
}

impl CertificateParams {
	/// Generate certificate parameters with reasonable defaults
	pub fn new(subject_alt_names: impl Into<Vec<String>>) -> Result<Self, Error> {
		let subject_alt_names = subject_alt_names
			.into()
			.into_iter()
			.map(|s| {
				Ok(match IpAddr::from_str(&s) {
					Ok(ip) => SanType::IpAddress(ip),
					Err(_) => SanType::DnsName(s.try_into()?),
				})
			})
			.collect::<Result<Vec<_>, _>>()?;
		Ok(CertificateParams {
			subject_alt_names,
			..Default::default()
		})
	}

	/// Generate a new certificate from the given parameters, signed by the provided issuer.
	///
	/// The returned certificate will have its issuer field set to the subject of the
	/// provided `issuer`, and the authority key identifier extension will be populated using
	/// the subject public key of `issuer`. It will be signed by `issuer_key`.
	///
	/// Note that no validation of the `issuer` certificate is performed. Rcgen will not require
	/// the certificate to be a CA certificate, or have key usage extensions that allow signing.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn signed_by(
		self,
		public_key: &impl PublicKeyData,
		issuer: &Certificate,
		issuer_key: &KeyPair,
	) -> Result<Certificate, Error> {
		let issuer = Issuer {
			distinguished_name: &issuer.params.distinguished_name,
			key_identifier_method: &issuer.params.key_identifier_method,
			key_usages: &issuer.params.key_usages,
			key_pair: issuer_key,
		};

		let subject_public_key_info =
			yasna::construct_der(|writer| serialize_public_key_der(public_key, writer));
		let der = self.serialize_der_with_signer(public_key, issuer)?;
		Ok(Certificate {
			params: self,
			subject_public_key_info,
			der,
		})
	}

	/// Generates a new self-signed certificate from the given parameters.
	///
	/// The returned [`Certificate`] may be serialized using [`Certificate::der`] and
	/// [`Certificate::pem`].
	pub fn self_signed(self, key_pair: &KeyPair) -> Result<Certificate, Error> {
		let issuer = Issuer {
			distinguished_name: &self.distinguished_name,
			key_identifier_method: &self.key_identifier_method,
			key_usages: &self.key_usages,
			key_pair,
		};

		let subject_public_key_info = key_pair.public_key_der();
		let der = self.serialize_der_with_signer(key_pair, issuer)?;
		Ok(Certificate {
			params: self,
			subject_public_key_info,
			der,
		})
	}

	/// Parses an existing ca certificate from the ASCII PEM format.
	///
	/// See [`from_ca_cert_der`](Self::from_ca_cert_der) for more details.
	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	pub fn from_ca_cert_pem(pem_str: &str) -> Result<Self, Error> {
		let certificate = pem::parse(pem_str).or(Err(Error::CouldNotParseCertificate))?;
		Self::from_ca_cert_der(&certificate.contents().into())
	}

	/// Parses an existing ca certificate from the DER format.
	///
	/// This function is only of use if you have an existing CA certificate
	/// you would like to use to sign a certificate generated by `rcgen`.
	/// By providing the constructed [`CertificateParams`] and the [`KeyPair`]
	/// associated with your existing `ca_cert` you can use [`CertificateParams::signed_by()`]
	/// or [`crate::CertificateSigningRequestParams::signed_by()`] to issue new certificates
	/// using the CA cert.
	///
	/// In general this function only extracts the information needed for signing.
	/// Other attributes of the [`Certificate`] may be left as defaults.
	///
	/// This function assumes the provided certificate is a CA. It will not check
	/// for the presence of the `BasicConstraints` extension, or perform any other
	/// validation.
	///
	/// [`rustls_pemfile::certs()`] is often used to obtain a [`CertificateDer`] from PEM input.
	/// If you already have a byte slice containing DER, it can trivially be converted into
	/// [`CertificateDer`] using the [`Into`] trait.
	///
	/// [`rustls_pemfile::certs()`]: https://docs.rs/rustls-pemfile/latest/rustls_pemfile/fn.certs.html
	#[cfg(feature = "x509-parser")]
	pub fn from_ca_cert_der(ca_cert: &CertificateDer<'_>) -> Result<Self, Error> {
		let (_remainder, x509) = x509_parser::parse_x509_certificate(ca_cert)
			.or(Err(Error::CouldNotParseCertificate))?;

		let dn = DistinguishedName::from_name(&x509.tbs_certificate.subject)?;
		let is_ca = Self::convert_x509_is_ca(&x509)?;
		let validity = x509.validity();
		let subject_alt_names = Self::convert_x509_subject_alternative_name(&x509)?;
		let key_usages = Self::convert_x509_key_usages(&x509)?;
		let extended_key_usages = Self::convert_x509_extended_key_usages(&x509)?;
		let name_constraints = Self::convert_x509_name_constraints(&x509)?;
		let serial_number = Some(x509.serial.to_bytes_be().into());

		let key_identifier_method =
			x509.iter_extensions()
				.find_map(|ext| match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
						Some(KeyIdMethod::PreSpecified(key_id.0.into()))
					},
					_ => None,
				});

		let key_identifier_method = match key_identifier_method {
			Some(method) => method,
			None => {
				#[cfg(not(feature = "crypto"))]
				return Err(Error::UnsupportedSignatureAlgorithm);
				#[cfg(feature = "crypto")]
				KeyIdMethod::Sha256
			},
		};

		Ok(CertificateParams {
			is_ca,
			subject_alt_names,
			key_usages,
			extended_key_usages,
			name_constraints,
			serial_number,
			key_identifier_method,
			distinguished_name: dn,
			not_before: validity.not_before.to_datetime(),
			not_after: validity.not_after.to_datetime(),
			..Default::default()
		})
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_is_ca(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<IsCa, Error> {
		use x509_parser::extensions::BasicConstraints as B;

		let basic_constraints = x509
			.basic_constraints()
			.or(Err(Error::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		let is_ca = match basic_constraints {
			Some(B {
				ca: true,
				path_len_constraint: Some(n),
			}) if *n <= u8::MAX as u32 => IsCa::Ca(BasicConstraints::Constrained(*n as u8)),
			Some(B {
				ca: true,
				path_len_constraint: Some(_),
			}) => return Err(Error::CouldNotParseCertificate),
			Some(B {
				ca: true,
				path_len_constraint: None,
			}) => IsCa::Ca(BasicConstraints::Unconstrained),
			Some(B { ca: false, .. }) => IsCa::ExplicitNoCa,
			None => IsCa::NoCa,
		};

		Ok(is_ca)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_subject_alternative_name(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<SanType>, Error> {
		let sans = x509
			.subject_alternative_name()
			.or(Err(Error::CouldNotParseCertificate))?
			.map(|ext| &ext.value.general_names);

		if let Some(sans) = sans {
			let mut subject_alt_names = Vec::with_capacity(sans.len());
			for san in sans {
				subject_alt_names.push(SanType::try_from_general(san)?);
			}
			Ok(subject_alt_names)
		} else {
			Ok(Vec::new())
		}
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_key_usages(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<KeyUsagePurpose>, Error> {
		let key_usage = x509
			.key_usage()
			.or(Err(Error::CouldNotParseCertificate))?
			.map(|ext| ext.value);
		// This x509 parser stores flags in reversed bit BIT STRING order
		let flags = key_usage.map_or(0u16, |k| k.flags).reverse_bits();
		Ok(KeyUsagePurpose::from_u16(flags))
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_extended_key_usages(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Vec<ExtendedKeyUsagePurpose>, Error> {
		let extended_key_usage = x509
			.extended_key_usage()
			.or(Err(Error::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		let mut extended_key_usages = Vec::new();
		if let Some(extended_key_usage) = extended_key_usage {
			if extended_key_usage.any {
				extended_key_usages.push(ExtendedKeyUsagePurpose::Any);
			}
			if extended_key_usage.server_auth {
				extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
			}
			if extended_key_usage.client_auth {
				extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
			}
			if extended_key_usage.code_signing {
				extended_key_usages.push(ExtendedKeyUsagePurpose::CodeSigning);
			}
			if extended_key_usage.email_protection {
				extended_key_usages.push(ExtendedKeyUsagePurpose::EmailProtection);
			}
			if extended_key_usage.time_stamping {
				extended_key_usages.push(ExtendedKeyUsagePurpose::TimeStamping);
			}
			if extended_key_usage.ocsp_signing {
				extended_key_usages.push(ExtendedKeyUsagePurpose::OcspSigning);
			}
		}
		Ok(extended_key_usages)
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_name_constraints(
		x509: &x509_parser::certificate::X509Certificate<'_>,
	) -> Result<Option<NameConstraints>, Error> {
		let constraints = x509
			.name_constraints()
			.or(Err(Error::CouldNotParseCertificate))?
			.map(|ext| ext.value);

		if let Some(constraints) = constraints {
			let permitted_subtrees = if let Some(permitted) = &constraints.permitted_subtrees {
				Self::convert_x509_general_subtrees(permitted)?
			} else {
				Vec::new()
			};

			let excluded_subtrees = if let Some(excluded) = &constraints.excluded_subtrees {
				Self::convert_x509_general_subtrees(excluded)?
			} else {
				Vec::new()
			};

			let name_constraints = NameConstraints {
				permitted_subtrees,
				excluded_subtrees,
			};

			Ok(Some(name_constraints))
		} else {
			Ok(None)
		}
	}
	#[cfg(feature = "x509-parser")]
	fn convert_x509_general_subtrees(
		subtrees: &[x509_parser::extensions::GeneralSubtree<'_>],
	) -> Result<Vec<GeneralSubtree>, Error> {
		use x509_parser::extensions::GeneralName;

		let mut result = Vec::new();
		for subtree in subtrees {
			let subtree = match &subtree.base {
				GeneralName::RFC822Name(s) => GeneralSubtree::Rfc822Name(s.to_string()),
				GeneralName::DNSName(s) => GeneralSubtree::DnsName(s.to_string()),
				GeneralName::DirectoryName(n) => {
					GeneralSubtree::DirectoryName(DistinguishedName::from_name(n)?)
				},
				GeneralName::IPAddress(bytes) if bytes.len() == 8 => {
					let addr: [u8; 4] = bytes[..4].try_into().unwrap();
					let mask: [u8; 4] = bytes[4..].try_into().unwrap();
					GeneralSubtree::IpAddress(CidrSubnet::V4(addr, mask))
				},
				GeneralName::IPAddress(bytes) if bytes.len() == 32 => {
					let addr: [u8; 16] = bytes[..16].try_into().unwrap();
					let mask: [u8; 16] = bytes[16..].try_into().unwrap();
					GeneralSubtree::IpAddress(CidrSubnet::V6(addr, mask))
				},
				_ => continue,
			};
			result.push(subtree);
		}
		Ok(result)
	}

	/// Write a CSR extension request attribute as defined in [RFC 2985].
	///
	/// [RFC 2985]: <https://datatracker.ietf.org/doc/html/rfc2985>
	fn write_extension_request_attribute(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&ObjectIdentifier::from_slice(
				oid::PKCS_9_AT_EXTENSION_REQUEST,
			));
			writer.next().write_set(|writer| {
				writer.next().write_sequence(|writer| {
					// Write key_usage
					self.write_key_usage(writer.next());
					// Write subject_alt_names
					self.write_subject_alt_names(writer.next());
					self.write_extended_key_usage(writer.next());

					// Write custom extensions
					for ext in &self.custom_extensions {
						write_x509_extension(writer.next(), &ext.oid, ext.critical, |writer| {
							writer.write_der(ext.content())
						});
					}
				});
			});
		});
	}

	/// Write a certificate's KeyUsage as defined in RFC 5280.
	fn write_key_usage(&self, writer: DERWriter) {
		// RFC 5280 defines 9 key usages, which we detail in our key usage enum
		// We could use std::mem::variant_count here, but it's experimental
		const KEY_USAGE_BITS: usize = 9;
		if self.key_usages.is_empty() {
			return;
		}

		// "When present, conforming CAs SHOULD mark this extension as critical."
		write_x509_extension(writer, oid::KEY_USAGE, true, |writer| {
			// u16 is large enough to encode the largest possible key usage (two-bytes)
			let bit_string = self.key_usages.iter().fold(0u16, |bit_string, key_usage| {
				bit_string | key_usage.to_u16()
			});
			writer.write_bitvec_bytes(&bit_string.to_be_bytes(), KEY_USAGE_BITS);
		});
	}

	fn write_extended_key_usage(&self, writer: DERWriter) {
		if !self.extended_key_usages.is_empty() {
			write_x509_extension(writer, oid::EXT_KEY_USAGE, false, |writer| {
				writer.write_sequence(|writer| {
					for usage in &self.extended_key_usages {
						writer
							.next()
							.write_oid(&ObjectIdentifier::from_slice(usage.oid()));
					}
				});
			});
		}
	}

	fn write_subject_alt_names(&self, writer: DERWriter) {
		if self.subject_alt_names.is_empty() {
			return;
		}

		write_x509_extension(writer, oid::SUBJECT_ALT_NAME, false, |writer| {
			writer.write_sequence(|writer| {
				for san in self.subject_alt_names.iter() {
					writer.next().write_tagged_implicit(
						Tag::context(san.tag()),
						|writer| match san {
							SanType::Rfc822Name(name)
							| SanType::DnsName(name)
							| SanType::URI(name) => writer.write_ia5_string(name.as_str()),
							SanType::IpAddress(IpAddr::V4(addr)) => {
								writer.write_bytes(&addr.octets())
							},
							SanType::IpAddress(IpAddr::V6(addr)) => {
								writer.write_bytes(&addr.octets())
							},
							SanType::OtherName((oid, value)) => {
								// otherName SEQUENCE { OID, [0] explicit any defined by oid }
								// https://datatracker.ietf.org/doc/html/rfc5280#page-38
								writer.write_sequence(|writer| {
									writer.next().write_oid(&ObjectIdentifier::from_slice(oid));
									value.write_der(writer.next());
								});
							},
						},
					);
				}
			});
		});
	}

	/// Generate and serialize a certificate signing request (CSR).
	///
	/// The constructed CSR will contain attributes based on the certificate parameters,
	/// and include the subject public key information from `subject_key`. Additionally,
	/// the CSR will be signed using the subject key.
	///
	/// Note that subsequent invocations of `serialize_request()` will not produce the exact
	/// same output.
	pub fn serialize_request(
		&self,
		subject_key: &KeyPair,
	) -> Result<CertificateSigningRequest, Error> {
		self.serialize_request_with_attributes(subject_key, Vec::new())
	}

	/// Generate and serialize a certificate signing request (CSR) with custom PKCS #10 attributes.
	/// as defined in [RFC 2986].
	///
	/// The constructed CSR will contain attributes based on the certificate parameters,
	/// and include the subject public key information from `subject_key`. Additionally,
	/// the CSR will be self-signed using the subject key.
	///
	/// Note that subsequent invocations of `serialize_request_with_attributes()` will not produce the exact
	/// same output.
	///
	/// [RFC 2986]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
	pub fn serialize_request_with_attributes(
		&self,
		subject_key: &KeyPair,
		attrs: Vec<Attribute>,
	) -> Result<CertificateSigningRequest, Error> {
		// No .. pattern, we use this to ensure every field is used
		#[deny(unused)]
		let Self {
			not_before,
			not_after,
			serial_number,
			subject_alt_names,
			distinguished_name,
			is_ca,
			key_usages,
			extended_key_usages,
			name_constraints,
			crl_distribution_points,
			custom_extensions,
			use_authority_key_identifier_extension,
			key_identifier_method,
		} = self;
		// - alg and key_pair will be used by the caller
		// - not_before and not_after cannot be put in a CSR
		// - key_identifier_method is here because self.write_extended_key_usage uses it
		// - There might be a use case for specifying the key identifier
		// in the CSR, but in the current API it can't be distinguished
		// from the defaults so this is left for a later version if
		// needed.
		let _ = (
			not_before,
			not_after,
			key_identifier_method,
			extended_key_usages,
		);
		if serial_number.is_some()
			|| *is_ca != IsCa::NoCa
			|| name_constraints.is_some()
			|| !crl_distribution_points.is_empty()
			|| *use_authority_key_identifier_extension
		{
			return Err(Error::UnsupportedInCsr);
		}

		// Whether or not to write an extension request attribute
		let write_extension_request = !key_usages.is_empty()
			|| !subject_alt_names.is_empty()
			|| !extended_key_usages.is_empty()
			|| !custom_extensions.is_empty();

		let der = subject_key.sign_der(|writer| {
			// Write version
			writer.next().write_u8(0);
			write_distinguished_name(writer.next(), distinguished_name);
			serialize_public_key_der(subject_key, writer.next());

			// According to the spec in RFC 2986, even if attributes are empty we need the empty attribute tag
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| {
					// RFC 2986 specifies that attributes are a SET OF Attribute
					writer.write_set_of(|writer| {
						if write_extension_request {
							self.write_extension_request_attribute(writer.next());
						}

						for Attribute { oid, values } in attrs {
							writer.next().write_sequence(|writer| {
								writer.next().write_oid(&ObjectIdentifier::from_slice(&oid));
								writer.next().write_der(&values);
							});
						}
					});
				});

			Ok(())
		})?;

		Ok(CertificateSigningRequest {
			der: CertificateSigningRequestDer::from(der),
		})
	}

	pub(crate) fn serialize_der_with_signer<K: PublicKeyData>(
		&self,
		pub_key: &K,
		issuer: Issuer<'_>,
	) -> Result<CertificateDer<'static>, Error> {
		let der = issuer.key_pair.sign_der(|writer| {
			let pub_key_spki =
				yasna::construct_der(|writer| serialize_public_key_der(pub_key, writer));
			// Write version
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_u8(2);
			});
			// Write serialNumber
			if let Some(ref serial) = self.serial_number {
				writer.next().write_bigint_bytes(serial.as_ref(), true);
			} else {
				#[cfg(feature = "crypto")]
				{
					let hash = digest::digest(&digest::SHA256, pub_key.der_bytes());
					// RFC 5280 specifies at most 20 bytes for a serial number
					let mut sl = hash.as_ref()[0..20].to_vec();
					sl[0] &= 0x7f; // MSB must be 0 to ensure encoding bignum in 20 bytes
					writer.next().write_bigint_bytes(&sl, true);
				}
				#[cfg(not(feature = "crypto"))]
				if self.serial_number.is_none() {
					return Err(Error::MissingSerialNumber);
				}
			};
			// Write signature algorithm
			issuer.key_pair.alg.write_alg_ident(writer.next());
			// Write issuer name
			write_distinguished_name(writer.next(), &issuer.distinguished_name);
			// Write validity
			writer.next().write_sequence(|writer| {
				// Not before
				write_dt_utc_or_generalized(writer.next(), self.not_before);
				// Not after
				write_dt_utc_or_generalized(writer.next(), self.not_after);
				Ok::<(), Error>(())
			})?;
			// Write subject
			write_distinguished_name(writer.next(), &self.distinguished_name);
			// Write subjectPublicKeyInfo
			serialize_public_key_der(pub_key, writer.next());
			// write extensions
			let should_write_exts = self.use_authority_key_identifier_extension
				|| !self.subject_alt_names.is_empty()
				|| !self.extended_key_usages.is_empty()
				|| self.name_constraints.iter().any(|c| !c.is_empty())
				|| matches!(self.is_ca, IsCa::ExplicitNoCa)
				|| matches!(self.is_ca, IsCa::Ca(_))
				|| !self.custom_extensions.is_empty();
			if !should_write_exts {
				return Ok(());
			}

			writer.next().write_tagged(Tag::context(3), |writer| {
				writer.write_sequence(|writer| {
					if self.use_authority_key_identifier_extension {
						write_x509_authority_key_identifier(
							writer.next(),
							match issuer.key_identifier_method {
								KeyIdMethod::PreSpecified(aki) => aki.clone(),
								#[cfg(feature = "crypto")]
								_ => issuer
									.key_identifier_method
									.derive(issuer.key_pair.public_key_der()),
							},
						);
					}
					// Write subject_alt_names
					if !self.subject_alt_names.is_empty() {
						self.write_subject_alt_names(writer.next());
					}

					// Write standard key usage
					self.write_key_usage(writer.next());

					// Write extended key usage
					if !self.extended_key_usages.is_empty() {
						write_x509_extension(writer.next(), oid::EXT_KEY_USAGE, false, |writer| {
							writer.write_sequence(|writer| {
								for usage in self.extended_key_usages.iter() {
									let oid = ObjectIdentifier::from_slice(usage.oid());
									writer.next().write_oid(&oid);
								}
							});
						});
					}
					if let Some(name_constraints) = &self.name_constraints {
						// If both trees are empty, the extension must be omitted.
						if !name_constraints.is_empty() {
							write_x509_extension(
								writer.next(),
								oid::NAME_CONSTRAINTS,
								true,
								|writer| {
									writer.write_sequence(|writer| {
										if !name_constraints.permitted_subtrees.is_empty() {
											write_general_subtrees(
												writer.next(),
												0,
												&name_constraints.permitted_subtrees,
											);
										}
										if !name_constraints.excluded_subtrees.is_empty() {
											write_general_subtrees(
												writer.next(),
												1,
												&name_constraints.excluded_subtrees,
											);
										}
									});
								},
							);
						}
					}
					if !self.crl_distribution_points.is_empty() {
						write_x509_extension(
							writer.next(),
							oid::CRL_DISTRIBUTION_POINTS,
							false,
							|writer| {
								writer.write_sequence(|writer| {
									for distribution_point in &self.crl_distribution_points {
										distribution_point.write_der(writer.next());
									}
								})
							},
						);
					}
					match self.is_ca {
						IsCa::Ca(ref constraint) => {
							// Write subject_key_identifier
							write_x509_extension(
								writer.next(),
								oid::SUBJECT_KEY_IDENTIFIER,
								false,
								|writer| {
									writer.write_bytes(
										&self.key_identifier_method.derive(pub_key_spki),
									);
								},
							);
							// Write basic_constraints
							write_x509_extension(
								writer.next(),
								oid::BASIC_CONSTRAINTS,
								true,
								|writer| {
									writer.write_sequence(|writer| {
										writer.next().write_bool(true); // cA flag
										if let BasicConstraints::Constrained(path_len_constraint) =
											constraint
										{
											writer.next().write_u8(*path_len_constraint);
										}
									});
								},
							);
						},
						IsCa::ExplicitNoCa => {
							// Write subject_key_identifier
							write_x509_extension(
								writer.next(),
								oid::SUBJECT_KEY_IDENTIFIER,
								false,
								|writer| {
									writer.write_bytes(
										&self.key_identifier_method.derive(pub_key_spki),
									);
								},
							);
							// Write basic_constraints
							write_x509_extension(
								writer.next(),
								oid::BASIC_CONSTRAINTS,
								true,
								|writer| {
									writer.write_sequence(|writer| {
										writer.next().write_bool(false); // cA flag
									});
								},
							);
						},
						IsCa::NoCa => {},
					}

					// Write the custom extensions
					for ext in &self.custom_extensions {
						write_x509_extension(writer.next(), &ext.oid, ext.critical, |writer| {
							writer.write_der(ext.content())
						});
					}
				});
			});

			Ok(())
		})?;

		Ok(der.into())
	}

	/// Insert an extended key usage (EKU) into the parameters if it does not already exist
	pub fn insert_extended_key_usage(&mut self, eku: ExtendedKeyUsagePurpose) {
		if !self.extended_key_usages.contains(&eku) {
			self.extended_key_usages.push(eku);
		}
	}
}

fn write_general_subtrees(writer: DERWriter, tag: u64, general_subtrees: &[GeneralSubtree]) {
	writer.write_tagged_implicit(Tag::context(tag), |writer| {
		writer.write_sequence(|writer| {
			for subtree in general_subtrees.iter() {
				writer.next().write_sequence(|writer| {
					writer
						.next()
						.write_tagged_implicit(
							Tag::context(subtree.tag()),
							|writer| match subtree {
								GeneralSubtree::Rfc822Name(name)
								| GeneralSubtree::DnsName(name) => writer.write_ia5_string(name),
								GeneralSubtree::DirectoryName(name) => {
									write_distinguished_name(writer, name)
								},
								GeneralSubtree::IpAddress(subnet) => {
									writer.write_bytes(&subnet.to_bytes())
								},
							},
						);
					// minimum must be 0 (the default) and maximum must be absent
				});
			}
		});
	});
}

/// A PKCS #10 CSR attribute, as defined in [RFC 5280] and constrained
/// by [RFC 2986].
///
/// [RFC 5280]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
/// [RFC 2986]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Attribute {
	/// `AttributeType` of the `Attribute`, defined as an `OBJECT IDENTIFIER`.
	pub oid: &'static [u64],
	/// DER-encoded values of the `Attribute`, defined by [RFC 2986] as:
	///
	/// ```text
	/// SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
	/// ```
	///
	/// [RFC 2986]: https://datatracker.ietf.org/doc/html/rfc2986#section-4
	pub values: Vec<u8>,
}

/// A custom extension of a certificate, as specified in
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CustomExtension {
	oid: Vec<u64>,
	critical: bool,

	/// The content must be DER-encoded
	content: Vec<u8>,
}

impl CustomExtension {
	/// Creates a new acmeIdentifier extension for ACME TLS-ALPN-01
	/// as specified in [RFC 8737](https://tools.ietf.org/html/rfc8737#section-3)
	///
	/// Panics if the passed `sha_digest` parameter doesn't hold 32 bytes (256 bits).
	pub fn new_acme_identifier(sha_digest: &[u8]) -> Self {
		assert_eq!(sha_digest.len(), 32, "wrong size of sha_digest");
		let content = yasna::construct_der(|writer| {
			writer.write_bytes(sha_digest);
		});
		Self {
			oid: oid::PE_ACME.to_owned(),
			critical: true,
			content,
		}
	}
	/// Create a new custom extension with the specified content
	pub fn from_oid_content(oid: &[u64], content: Vec<u8>) -> Self {
		Self {
			oid: oid.to_owned(),
			critical: false,
			content,
		}
	}
	/// Sets the criticality flag of the extension.
	pub fn set_criticality(&mut self, criticality: bool) {
		self.critical = criticality;
	}
	/// Obtains the criticality flag of the extension.
	pub fn criticality(&self) -> bool {
		self.critical
	}
	/// Obtains the content of the extension.
	pub fn content(&self) -> &[u8] {
		&self.content
	}
	/// Obtains the OID components of the extensions, as u64 pieces
	pub fn oid_components(&self) -> impl Iterator<Item = u64> + '_ {
		self.oid.iter().copied()
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
/// The attribute type of a distinguished name entry
pub enum DnType {
	/// X520countryName
	CountryName,
	/// X520LocalityName
	LocalityName,
	/// X520StateOrProvinceName
	StateOrProvinceName,
	/// X520OrganizationName
	OrganizationName,
	/// X520OrganizationalUnitName
	OrganizationalUnitName,
	/// X520CommonName
	CommonName,
	/// Custom distinguished name type
	CustomDnType(Vec<u64>),
}

impl DnType {
	pub(crate) fn to_oid(&self) -> ObjectIdentifier {
		let sl = match self {
			DnType::CountryName => oid::COUNTRY_NAME,
			DnType::LocalityName => oid::LOCALITY_NAME,
			DnType::StateOrProvinceName => oid::STATE_OR_PROVINCE_NAME,
			DnType::OrganizationName => oid::ORG_NAME,
			DnType::OrganizationalUnitName => oid::ORG_UNIT_NAME,
			DnType::CommonName => oid::COMMON_NAME,
			DnType::CustomDnType(ref oid) => oid.as_slice(),
		};
		ObjectIdentifier::from_slice(sl)
	}

	/// Generate a DnType for the provided OID
	pub fn from_oid(slice: &[u64]) -> Self {
		match slice {
			oid::COUNTRY_NAME => DnType::CountryName,
			oid::LOCALITY_NAME => DnType::LocalityName,
			oid::STATE_OR_PROVINCE_NAME => DnType::StateOrProvinceName,
			oid::ORG_NAME => DnType::OrganizationName,
			oid::ORG_UNIT_NAME => DnType::OrganizationalUnitName,
			oid::COMMON_NAME => DnType::CommonName,
			oid => DnType::CustomDnType(oid.into()),
		}
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// One of the purposes contained in the [extended key usage extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
pub enum ExtendedKeyUsagePurpose {
	/// anyExtendedKeyUsage
	Any,
	/// id-kp-serverAuth
	ServerAuth,
	/// id-kp-clientAuth
	ClientAuth,
	/// id-kp-codeSigning
	CodeSigning,
	/// id-kp-emailProtection
	EmailProtection,
	/// id-kp-timeStamping
	TimeStamping,
	/// id-kp-OCSPSigning
	OcspSigning,
	/// A custom purpose not from the pre-specified list of purposes
	Other(Vec<u64>),
}

impl ExtendedKeyUsagePurpose {
	fn oid(&self) -> &[u64] {
		use ExtendedKeyUsagePurpose::*;
		match self {
			// anyExtendedKeyUsage
			Any => &[2, 5, 29, 37, 0],
			// id-kp-*
			ServerAuth => &[1, 3, 6, 1, 5, 5, 7, 3, 1],
			ClientAuth => &[1, 3, 6, 1, 5, 5, 7, 3, 2],
			CodeSigning => &[1, 3, 6, 1, 5, 5, 7, 3, 3],
			EmailProtection => &[1, 3, 6, 1, 5, 5, 7, 3, 4],
			TimeStamping => &[1, 3, 6, 1, 5, 5, 7, 3, 8],
			OcspSigning => &[1, 3, 6, 1, 5, 5, 7, 3, 9],
			Other(oid) => oid,
		}
	}
}

/// The [NameConstraints extension](https://tools.ietf.org/html/rfc5280#section-4.2.1.10)
/// (only relevant for CA certificates)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameConstraints {
	/// A list of subtrees that the domain has to match.
	pub permitted_subtrees: Vec<GeneralSubtree>,
	/// A list of subtrees that the domain must not match.
	///
	/// Any name matching an excluded subtree is invalid even if it also matches a permitted subtree.
	pub excluded_subtrees: Vec<GeneralSubtree>,
}

impl NameConstraints {
	fn is_empty(&self) -> bool {
		self.permitted_subtrees.is_empty() && self.excluded_subtrees.is_empty()
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// General Subtree type.
///
/// This type has similarities to the [`SanType`] enum but is not equal.
/// For example, `GeneralSubtree` has CIDR subnets for ip addresses
/// while [`SanType`] has IP addresses.
pub enum GeneralSubtree {
	/// Also known as E-Mail address
	Rfc822Name(String),
	DnsName(String),
	DirectoryName(DistinguishedName),
	IpAddress(CidrSubnet),
}

impl GeneralSubtree {
	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_RFC822_NAME: u64 = 1;
		const TAG_DNS_NAME: u64 = 2;
		const TAG_DIRECTORY_NAME: u64 = 4;
		const TAG_IP_ADDRESS: u64 = 7;

		match self {
			GeneralSubtree::Rfc822Name(_name) => TAG_RFC822_NAME,
			GeneralSubtree::DnsName(_name) => TAG_DNS_NAME,
			GeneralSubtree::DirectoryName(_name) => TAG_DIRECTORY_NAME,
			GeneralSubtree::IpAddress(_addr) => TAG_IP_ADDRESS,
		}
	}
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
/// CIDR subnet, as per [RFC 4632](https://tools.ietf.org/html/rfc4632)
///
/// You might know CIDR subnets better by their textual representation
/// where they consist of an ip address followed by a slash and a prefix
/// number, for example `192.168.99.0/24`.
///
/// The first field in the enum is the address, the second is the mask.
/// Both are specified in network byte order.
pub enum CidrSubnet {
	V4([u8; 4], [u8; 4]),
	V6([u8; 16], [u8; 16]),
}

macro_rules! mask {
	($t:ty, $d:expr) => {{
		let v = <$t>::max_value();
		let v = v.checked_shr($d as u32).unwrap_or(0);
		(!v).to_be_bytes()
	}};
}

impl CidrSubnet {
	/// Obtains the CidrSubnet from an ip address
	/// as well as the specified prefix number.
	///
	/// ```
	/// # use std::net::IpAddr;
	/// # use std::str::FromStr;
	/// # use rcgen::CidrSubnet;
	/// // The "192.0.2.0/24" example from
	/// // https://tools.ietf.org/html/rfc5280#page-42
	/// let addr = IpAddr::from_str("192.0.2.0").unwrap();
	/// let subnet = CidrSubnet::from_addr_prefix(addr, 24);
	/// assert_eq!(subnet, CidrSubnet::V4([0xC0, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0x00]));
	/// ```
	pub fn from_addr_prefix(addr: IpAddr, prefix: u8) -> Self {
		match addr {
			IpAddr::V4(addr) => Self::from_v4_prefix(addr.octets(), prefix),
			IpAddr::V6(addr) => Self::from_v6_prefix(addr.octets(), prefix),
		}
	}
	/// Obtains the CidrSubnet from an IPv4 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v4_prefix(addr: [u8; 4], prefix: u8) -> Self {
		CidrSubnet::V4(addr, mask!(u32, prefix))
	}
	/// Obtains the CidrSubnet from an IPv6 address in network byte order
	/// as well as the specified prefix.
	pub fn from_v6_prefix(addr: [u8; 16], prefix: u8) -> Self {
		CidrSubnet::V6(addr, mask!(u128, prefix))
	}
	fn to_bytes(&self) -> Vec<u8> {
		let mut res = Vec::new();
		match self {
			CidrSubnet::V4(addr, mask) => {
				res.extend_from_slice(addr);
				res.extend_from_slice(mask);
			},
			CidrSubnet::V6(addr, mask) => {
				res.extend_from_slice(addr);
				res.extend_from_slice(mask);
			},
		}
		res
	}
}

/// Obtains the CidrSubnet from the well-known
/// addr/prefix notation.
/// ```
/// # use std::str::FromStr;
/// # use rcgen::CidrSubnet;
/// // The "192.0.2.0/24" example from
/// // https://tools.ietf.org/html/rfc5280#page-42
/// let subnet = CidrSubnet::from_str("192.0.2.0/24").unwrap();
/// assert_eq!(subnet, CidrSubnet::V4([0xC0, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0x00]));
/// ```
impl FromStr for CidrSubnet {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut iter = s.split('/');
		if let (Some(addr_s), Some(prefix_s)) = (iter.next(), iter.next()) {
			let addr = IpAddr::from_str(addr_s).map_err(|_| ())?;
			let prefix = u8::from_str(prefix_s).map_err(|_| ())?;
			Ok(Self::from_addr_prefix(addr, prefix))
		} else {
			Err(())
		}
	}
}

/// Helper to obtain an `OffsetDateTime` from year, month, day values
///
/// The year, month, day values are assumed to be in UTC.
///
/// This helper function serves two purposes: first, so that you don't
/// have to import the time crate yourself in order to specify date
/// information, second so that users don't have to type unproportionately
/// long code just to generate an instance of [`OffsetDateTime`].
pub fn date_time_ymd(year: i32, month: u8, day: u8) -> OffsetDateTime {
	let month = Month::try_from(month).expect("out-of-range month");
	let primitive_dt = PrimitiveDateTime::new(
		Date::from_calendar_date(year, month, day).expect("invalid or out-of-range date"),
		Time::MIDNIGHT,
	);
	primitive_dt.assume_utc()
}

/// Whether the certificate is allowed to sign other certificates
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum IsCa {
	/// The certificate can only sign itself
	NoCa,
	/// The certificate can only sign itself, adding the extension and `CA:FALSE`
	ExplicitNoCa,
	/// The certificate may be used to sign other certificates
	Ca(BasicConstraints),
}

/// The path length constraint (only relevant for CA certificates)
///
/// Sets an optional upper limit on the length of the intermediate certificate chain
/// length allowed for this CA certificate (not including the end entity certificate).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum BasicConstraints {
	/// No constraint
	Unconstrained,
	/// Constrain to the contained number of intermediate certificates
	Constrained(u8),
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "pem")]
	use super::*;

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_key_usages() {
		let mut params: CertificateParams = Default::default();

		// Set key_usages
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::ContentCommitment,
		];

		// This can sign things!
		params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Check oid
		let key_usage_oid_str = "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::KeyUsage(usage) => {
						assert!(usage.flags == 7);
						found = true;
					},
					_ => {},
				}
			}
		}

		assert!(found);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_key_usages_decipheronly_only() {
		let mut params: CertificateParams = Default::default();

		// Set key_usages
		params.key_usages = vec![KeyUsagePurpose::DecipherOnly];

		// This can sign things!
		params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Check oid
		let key_usage_oid_str = "2.5.29.15";

		// Found flag
		let mut found = false;

		for ext in cert.extensions() {
			if key_usage_oid_str == ext.oid.to_id_string() {
				match ext.parsed_extension() {
					x509_parser::extensions::ParsedExtension::KeyUsage(usage) => {
						assert!(usage.flags == 256);
						found = true;
					},
					_ => {},
				}
			}
		}

		assert!(found);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_extended_key_usages_any() {
		let mut params: CertificateParams = Default::default();

		// Set extended_key_usages
		params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any];

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Ensure we found it.
		let maybe_extension = cert.extended_key_usage().unwrap();
		let extension = maybe_extension.unwrap();
		assert!(extension.value.any);
	}

	#[cfg(feature = "crypto")]
	#[test]
	fn test_with_extended_key_usages_other() {
		use x509_parser::der_parser::asn1_rs::Oid;
		let mut params: CertificateParams = Default::default();
		const OID_1: &[u64] = &[1, 2, 3, 4];
		const OID_2: &[u64] = &[1, 2, 3, 4, 5, 6];

		// Set extended_key_usages
		params.extended_key_usages = vec![
			ExtendedKeyUsagePurpose::Other(Vec::from(OID_1)),
			ExtendedKeyUsagePurpose::Other(Vec::from(OID_2)),
		];

		// Make the cert
		let key_pair = KeyPair::generate().unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Parse it
		let (_rem, cert) = x509_parser::parse_x509_certificate(cert.der()).unwrap();

		// Ensure we found it.
		let maybe_extension = cert.extended_key_usage().unwrap();
		let extension = maybe_extension.unwrap();

		let expected_oids = vec![Oid::from(OID_1).unwrap(), Oid::from(OID_2).unwrap()];
		assert_eq!(extension.value.other, expected_oids);
	}

	#[cfg(feature = "pem")]
	mod test_pem_serialization {
		use super::*;

		#[test]
		#[cfg(windows)]
		fn test_windows_line_endings() {
			let key_pair = KeyPair::generate().unwrap();
			let cert = CertificateParams::default().self_signed(&key_pair).unwrap();
			assert!(cert.pem().contains("\r\n"));
		}

		#[test]
		#[cfg(not(windows))]
		fn test_not_windows_line_endings() {
			let key_pair = KeyPair::generate().unwrap();
			let cert = CertificateParams::default().self_signed(&key_pair).unwrap();
			assert!(!cert.pem().contains('\r'));
		}
	}

	#[cfg(all(feature = "pem", feature = "x509-parser"))]
	mod test_key_identifier_from_ca {
		use super::*;

		#[test]
		fn load_ca_and_sign_cert() {
			let ca_cert = r#"-----BEGIN CERTIFICATE-----
MIIFDTCCAvWgAwIBAgIUVuDfDt/BUVfObGOHsM+L5/qPZfIwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMxMjA4MTAwOTI2WhcNMjQx
MTI4MTAwOTI2WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAKXyZsv7Zwek9yc54IXWjCkMwU4eDMz9Uw06WETF
hZtauwDo4usCeYJa/7x8RZbGcI99s/vOMHjIdVzY6g9p5c6qS+7EUBhXARYVB74z
XUGwgVGss7lgw+0dNxhQ8F0M2smBXUP9FlJJjJpbWeU+93iynGy+PTXFtYMnOoVI
4G7YKsG5lX0zBJUNYZslEz6Kp8eRYu7FAdccU0u5bmg02a1WiXOYJeN1+AifUbRN
zNInZCqMCFgoHczb0DvKU3QX/xrcBxfr/SNJPqxlecUvsozteUoAFAUF1uTxH31q
cVmCHf9I0r6JJoGxs+XMVbH2SJLdsq/+zpjeHz6gy0z4aRMBpaUWUQ9pEENeSq15
PXCuX3yPT2BII30mL86OWO6qgms70iALak6xZ/xAT7RT22E1bOF+XJsiUM3OgGF0
TPmDcpafEMH4kwzdaC7U5hqhYk9I2lfTMEghV86kUXClExuHEQD4GZLcd1HMD/Wg
qOZO4y/t/yzBPNq01FpeilFph/tW6pxr1X7Jloz1/yIuNFK0oXTB24J/TUi+/S1B
kavOBg3eNHHDXDjESKtnV+iwo1cFt6LVCrnKhKJ6m95+c+YKQGIrcwkR91OxZ9ZT
DEzySsPDpWrteZf3K1VA0Ut41aTKu8pYwxsnVdOiBGaJkOh/lrevI6U9Eg4vVq94
hyAZAgMBAAGjUzBRMB0GA1UdDgQWBBSX1HahmxpxNSrH9KGEElYGul1hhDAfBgNV
HSMEGDAWgBSX1HahmxpxNSrH9KGEElYGul1hhDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQAhtwt0OrHVITVOzoH3c+7SS/rGd9KGpHG4Z/N7ASs3
7A2PXFC5XbUuylky0+/nbkN6hhecj+Zwt5x5R8k4saXUZ8xkMfP8RaRxyZ3rUOIC
BZhZm1XbQzaWIQjpjyPUWDDa9P0lGsUyrEIQaLjg1J5jYPOD132bmdIuhZtzldTV
zeE/4sKdrkj6HZxe1jxAhx2IWm6W+pEAcq1Ld9SmJGOxBVRRKyGsMMw6hCdWfQHv
Z8qRIhn3FU6ZKW2jvTGJBIXoK4u454qi6DVxkFZ0OK9VwWVuDLvs2Es95TiZPTq+
KJmRHWHF/Ic78XFgxVq0tVaJAs7qoOMjDkehPG1V8eewanlpcaE6rPx0eiPq+nHE
gCf0KmKGVM8lQe63obzprkdLKL3T4UDN19K2wqscJcPKK++27OYx2hJaJKmYzF23
4WhIRzdALTs/2fbB68nVSz7kBtHvsHHS33Q57zEdQq5YeyUaTtCvJJobt70dy9vN
YolzLWoY/itEPFtbBAdnJxXlctI3bw4Mzw1d66Wt+//R45+cIe6cJdUIqMHDhsGf
U8EuffvDcTJuUzIkyzbyOI15r1TMbRt8vFR0jzagZBCG73lVacH/bYEb2j4Z1ORi
L2Fl4tgIQ5tyaTpu9gpJZvPU0VZ/j+1Jdk1c9PJ6xhCjof4nzI9YsLbI8lPtu8K/
Ng==
-----END CERTIFICATE-----"#;

			let ca_key = r#"-----BEGIN PRIVATE KEY-----
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
PITGdT9dgN88nHPCle0B1+OY+OZ5
-----END PRIVATE KEY-----"#;

			let params = CertificateParams::from_ca_cert_pem(ca_cert).unwrap();
			let ca_ski = vec![
				0x97, 0xD4, 0x76, 0xA1, 0x9B, 0x1A, 0x71, 0x35, 0x2A, 0xC7, 0xF4, 0xA1, 0x84, 0x12,
				0x56, 0x06, 0xBA, 0x5D, 0x61, 0x84,
			];

			assert_eq!(
				KeyIdMethod::PreSpecified(ca_ski.clone()),
				params.key_identifier_method
			);

			let ca_kp = KeyPair::from_pem(ca_key).unwrap();
			let ca_cert = params.self_signed(&ca_kp).unwrap();
			assert_eq!(&ca_ski, &ca_cert.key_identifier());

			let (_, x509_ca) = x509_parser::parse_x509_certificate(ca_cert.der()).unwrap();
			assert_eq!(
				&ca_ski,
				&x509_ca
					.iter_extensions()
					.find_map(|ext| match ext.parsed_extension() {
						x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
							Some(key_id.0.to_vec())
						},
						_ => None,
					})
					.unwrap()
			);

			let ee_key = KeyPair::generate().unwrap();
			let mut ee_params = CertificateParams::default();
			ee_params.use_authority_key_identifier_extension = true;
			let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ee_key).unwrap();

			let (_, x509_ee) = x509_parser::parse_x509_certificate(ee_cert.der()).unwrap();
			assert_eq!(
				&ca_ski,
				&x509_ee
					.iter_extensions()
					.find_map(|ext| match ext.parsed_extension() {
						x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
							aki.key_identifier.as_ref().map(|ki| ki.0.to_vec())
						},
						_ => None,
					})
					.unwrap()
			);
		}
	}
}
