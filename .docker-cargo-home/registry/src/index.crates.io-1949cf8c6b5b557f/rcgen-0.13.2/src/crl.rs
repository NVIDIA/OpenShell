#[cfg(feature = "pem")]
use pem::Pem;
use pki_types::CertificateRevocationListDer;
use time::OffsetDateTime;
use yasna::DERWriter;
use yasna::Tag;

#[cfg(feature = "pem")]
use crate::ENCODE_CONFIG;
use crate::{
	oid, write_distinguished_name, write_dt_utc_or_generalized,
	write_x509_authority_key_identifier, write_x509_extension, Certificate, Error, Issuer,
	KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
};

/// A certificate revocation list (CRL)
///
/// ## Example
///
/// ```
/// extern crate rcgen;
/// use rcgen::*;
///
/// #[cfg(not(feature = "crypto"))]
/// struct MyKeyPair { public_key: Vec<u8> }
/// #[cfg(not(feature = "crypto"))]
/// impl RemoteKeyPair for MyKeyPair {
///   fn public_key(&self) -> &[u8] { &self.public_key }
///   fn sign(&self, _: &[u8]) -> Result<Vec<u8>, rcgen::Error> { Ok(vec![]) }
///   fn algorithm(&self) -> &'static SignatureAlgorithm { &PKCS_ED25519 }
/// }
/// # fn main () {
/// // Generate a CRL issuer.
/// let mut issuer_params = CertificateParams::new(vec!["crl.issuer.example.com".to_string()]).unwrap();
/// issuer_params.serial_number = Some(SerialNumber::from(9999));
/// issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
/// issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::CrlSign];
/// #[cfg(feature = "crypto")]
/// let key_pair = KeyPair::generate().unwrap();
/// #[cfg(not(feature = "crypto"))]
/// let remote_key_pair = MyKeyPair { public_key: vec![] };
/// #[cfg(not(feature = "crypto"))]
/// let key_pair = KeyPair::from_remote(Box::new(remote_key_pair)).unwrap();
/// let issuer = issuer_params.self_signed(&key_pair).unwrap();
/// // Describe a revoked certificate.
/// let revoked_cert = RevokedCertParams{
///   serial_number: SerialNumber::from(9999),
///   revocation_time: date_time_ymd(2024, 06, 17),
///   reason_code: Some(RevocationReason::KeyCompromise),
///   invalidity_date: None,
/// };
/// // Create a CRL signed by the issuer, revoking revoked_cert.
/// let crl = CertificateRevocationListParams{
///   this_update: date_time_ymd(2023, 06, 17),
///   next_update: date_time_ymd(2024, 06, 17),
///   crl_number: SerialNumber::from(1234),
///   issuing_distribution_point: None,
///   revoked_certs: vec![revoked_cert],
///   #[cfg(feature = "crypto")]
///   key_identifier_method: KeyIdMethod::Sha256,
///   #[cfg(not(feature = "crypto"))]
///   key_identifier_method: KeyIdMethod::PreSpecified(vec![]),
/// }.signed_by(&issuer, &key_pair).unwrap();
///# }
pub struct CertificateRevocationList {
	params: CertificateRevocationListParams,
	der: CertificateRevocationListDer<'static>,
}

impl CertificateRevocationList {
	/// Returns the certificate revocation list (CRL) parameters.
	pub fn params(&self) -> &CertificateRevocationListParams {
		&self.params
	}

	/// Get the CRL in PEM encoded format.
	#[cfg(feature = "pem")]
	pub fn pem(&self) -> Result<String, Error> {
		let p = Pem::new("X509 CRL", &*self.der);
		Ok(pem::encode_config(&p, ENCODE_CONFIG))
	}

	/// Get the CRL in DER encoded format.
	///
	/// [`CertificateRevocationListDer`] implements `Deref<Target = [u8]>` and `AsRef<[u8]>`,
	/// so you can easily extract the DER bytes from the return value.
	pub fn der(&self) -> &CertificateRevocationListDer<'static> {
		&self.der
	}
}

impl From<CertificateRevocationList> for CertificateRevocationListDer<'static> {
	fn from(crl: CertificateRevocationList) -> Self {
		crl.der
	}
}

/// A certificate revocation list (CRL) distribution point, to be included in a certificate's
/// [distribution points extension](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13) or
/// a CRL's [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5)
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CrlDistributionPoint {
	/// One or more URI distribution point names, indicating a place the current CRL can
	/// be retrieved. When present, SHOULD include at least one LDAP or HTTP URI.
	pub uris: Vec<String>,
}

impl CrlDistributionPoint {
	pub(crate) fn write_der(&self, writer: DERWriter) {
		// DistributionPoint SEQUENCE
		writer.write_sequence(|writer| {
			write_distribution_point_name_uris(writer.next(), &self.uris);
		});
	}
}

fn write_distribution_point_name_uris<'a>(
	writer: DERWriter,
	uris: impl IntoIterator<Item = &'a String>,
) {
	// distributionPoint DistributionPointName
	writer.write_tagged_implicit(Tag::context(0), |writer| {
		writer.write_sequence(|writer| {
			// fullName GeneralNames
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| {
					// GeneralNames
					writer.write_sequence(|writer| {
						for uri in uris.into_iter() {
							// uniformResourceIdentifier [6] IA5String,
							writer
								.next()
								.write_tagged_implicit(Tag::context(6), |writer| {
									writer.write_ia5_string(uri)
								});
						}
					})
				});
		});
	});
}

/// Identifies the reason a certificate was revoked.
/// See [RFC 5280 §5.3.1][1]
///
/// [1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(missing_docs)] // Not much to add above the code name.
pub enum RevocationReason {
	Unspecified = 0,
	KeyCompromise = 1,
	CaCompromise = 2,
	AffiliationChanged = 3,
	Superseded = 4,
	CessationOfOperation = 5,
	CertificateHold = 6,
	// 7 is not defined.
	RemoveFromCrl = 8,
	PrivilegeWithdrawn = 9,
	AaCompromise = 10,
}

/// Parameters used for certificate revocation list (CRL) generation
pub struct CertificateRevocationListParams {
	/// Issue date of the CRL.
	pub this_update: OffsetDateTime,
	/// The date by which the next CRL will be issued.
	pub next_update: OffsetDateTime,
	/// A monotonically increasing sequence number for a given CRL scope and issuer.
	pub crl_number: SerialNumber,
	/// An optional CRL extension identifying the CRL distribution point and scope for a
	/// particular CRL as described in RFC 5280 Section 5.2.5[^1].
	///
	/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5>
	pub issuing_distribution_point: Option<CrlIssuingDistributionPoint>,
	/// A list of zero or more parameters describing revoked certificates included in the CRL.
	pub revoked_certs: Vec<RevokedCertParams>,
	/// Method to generate key identifiers from public keys
	///
	/// Defaults to SHA-256.
	pub key_identifier_method: KeyIdMethod,
}

impl CertificateRevocationListParams {
	/// Serializes the certificate revocation list (CRL).
	///
	/// Including a signature from the issuing certificate authority's key.
	pub fn signed_by(
		self,
		issuer: &Certificate,
		issuer_key: &KeyPair,
	) -> Result<CertificateRevocationList, Error> {
		if self.next_update.le(&self.this_update) {
			return Err(Error::InvalidCrlNextUpdate);
		}

		let issuer = Issuer {
			distinguished_name: &issuer.params.distinguished_name,
			key_identifier_method: &issuer.params.key_identifier_method,
			key_usages: &issuer.params.key_usages,
			key_pair: issuer_key,
		};

		if !issuer.key_usages.is_empty() && !issuer.key_usages.contains(&KeyUsagePurpose::CrlSign) {
			return Err(Error::IssuerNotCrlSigner);
		}

		Ok(CertificateRevocationList {
			der: self.serialize_der(issuer)?.into(),
			params: self,
		})
	}

	fn serialize_der(&self, issuer: Issuer) -> Result<Vec<u8>, Error> {
		issuer.key_pair.sign_der(|writer| {
			// Write CRL version.
			// RFC 5280 §5.1.2.1:
			//   This optional field describes the version of the encoded CRL.  When
			//   extensions are used, as required by this profile, this field MUST be
			//   present and MUST specify version 2 (the integer value is 1).
			// RFC 5280 §5.2:
			//   Conforming CRL issuers are REQUIRED to include the authority key
			//   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
			//   extensions in all CRLs issued.
			writer.next().write_u8(1);

			// Write algorithm identifier.
			// RFC 5280 §5.1.2.2:
			//   This field MUST contain the same algorithm identifier as the
			//   signatureAlgorithm field in the sequence CertificateList
			issuer.key_pair.alg.write_alg_ident(writer.next());

			// Write issuer.
			// RFC 5280 §5.1.2.3:
			//   The issuer field MUST contain a non-empty X.500 distinguished name (DN).
			write_distinguished_name(writer.next(), &issuer.distinguished_name);

			// Write thisUpdate date.
			// RFC 5280 §5.1.2.4:
			//    This field indicates the issue date of this CRL.  thisUpdate may be
			//    encoded as UTCTime or GeneralizedTime.
			write_dt_utc_or_generalized(writer.next(), self.this_update);

			// Write nextUpdate date.
			// While OPTIONAL in the ASN.1 module, RFC 5280 §5.1.2.5 says:
			//   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
			write_dt_utc_or_generalized(writer.next(), self.next_update);

			// Write revokedCertificates.
			// RFC 5280 §5.1.2.6:
			//   When there are no revoked certificates, the revoked certificates list
			//   MUST be absent
			if !self.revoked_certs.is_empty() {
				writer.next().write_sequence(|writer| {
					for revoked_cert in &self.revoked_certs {
						revoked_cert.write_der(writer.next());
					}
				});
			}

			// Write crlExtensions.
			// RFC 5280 §5.1.2.7:
			//   This field may only appear if the version is 2 (Section 5.1.2.1).  If
			//   present, this field is a sequence of one or more CRL extensions.
			// RFC 5280 §5.2:
			//   Conforming CRL issuers are REQUIRED to include the authority key
			//   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
			//   extensions in all CRLs issued.
			writer.next().write_tagged(Tag::context(0), |writer| {
				writer.write_sequence(|writer| {
					// Write authority key identifier.
					write_x509_authority_key_identifier(
						writer.next(),
						self.key_identifier_method
							.derive(issuer.key_pair.public_key_der()),
					);

					// Write CRL number.
					write_x509_extension(writer.next(), oid::CRL_NUMBER, false, |writer| {
						writer.write_bigint_bytes(self.crl_number.as_ref(), true);
					});

					// Write issuing distribution point (if present).
					if let Some(issuing_distribution_point) = &self.issuing_distribution_point {
						write_x509_extension(
							writer.next(),
							oid::CRL_ISSUING_DISTRIBUTION_POINT,
							true,
							|writer| {
								issuing_distribution_point.write_der(writer);
							},
						);
					}
				});
			});

			Ok(())
		})
	}
}

/// A certificate revocation list (CRL) issuing distribution point, to be included in a CRL's
/// [issuing distribution point extension](https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5).
pub struct CrlIssuingDistributionPoint {
	/// The CRL's distribution point, containing a sequence of URIs the CRL can be retrieved from.
	pub distribution_point: CrlDistributionPoint,
	/// An optional description of the CRL's scope. If omitted, the CRL may contain
	/// both user certs and CA certs.
	pub scope: Option<CrlScope>,
}

impl CrlIssuingDistributionPoint {
	fn write_der(&self, writer: DERWriter) {
		// IssuingDistributionPoint SEQUENCE
		writer.write_sequence(|writer| {
			// distributionPoint [0] DistributionPointName OPTIONAL
			write_distribution_point_name_uris(writer.next(), &self.distribution_point.uris);

			// -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
			// -- and onlyContainsAttributeCerts may be set to TRUE.
			if let Some(scope) = self.scope {
				let tag = match scope {
					// onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE,
					CrlScope::UserCertsOnly => Tag::context(1),
					// onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE,
					CrlScope::CaCertsOnly => Tag::context(2),
				};
				writer.next().write_tagged_implicit(tag, |writer| {
					writer.write_bool(true);
				});
			}
		});
	}
}

/// Describes the scope of a CRL for an issuing distribution point extension.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CrlScope {
	/// The CRL contains only end-entity user certificates.
	UserCertsOnly,
	/// The CRL contains only CA certificates.
	CaCertsOnly,
}

/// Parameters used for describing a revoked certificate included in a [`CertificateRevocationList`].
pub struct RevokedCertParams {
	/// Serial number identifying the revoked certificate.
	pub serial_number: SerialNumber,
	/// The date at which the CA processed the revocation.
	pub revocation_time: OffsetDateTime,
	/// An optional reason code identifying why the certificate was revoked.
	pub reason_code: Option<RevocationReason>,
	/// An optional field describing the date on which it was known or suspected that the
	/// private key was compromised or the certificate otherwise became invalid. This date
	/// may be earlier than the [`RevokedCertParams::revocation_time`].
	pub invalidity_date: Option<OffsetDateTime>,
}

impl RevokedCertParams {
	fn write_der(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			// Write serial number.
			// RFC 5280 §4.1.2.2:
			//    Certificate users MUST be able to handle serialNumber values up to 20 octets.
			//    Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
			//
			//    Note: Non-conforming CAs may issue certificates with serial numbers
			//    that are negative or zero.  Certificate users SHOULD be prepared to
			//    gracefully handle such certificates.
			writer
				.next()
				.write_bigint_bytes(self.serial_number.as_ref(), true);

			// Write revocation date.
			write_dt_utc_or_generalized(writer.next(), self.revocation_time);

			// Write extensions if applicable.
			// RFC 5280 §5.3:
			//   Support for the CRL entry extensions defined in this specification is
			//   optional for conforming CRL issuers and applications.  However, CRL
			//   issuers SHOULD include reason codes (Section 5.3.1) and invalidity
			//   dates (Section 5.3.2) whenever this information is available.
			let has_reason_code =
				matches!(self.reason_code, Some(reason) if reason != RevocationReason::Unspecified);
			let has_invalidity_date = self.invalidity_date.is_some();
			if has_reason_code || has_invalidity_date {
				writer.next().write_sequence(|writer| {
					// Write reason code if present.
					if let Some(reason_code) = self.reason_code {
						write_x509_extension(writer.next(), oid::CRL_REASONS, false, |writer| {
							writer.write_enum(reason_code as i64);
						});
					}

					// Write invalidity date if present.
					if let Some(invalidity_date) = self.invalidity_date {
						write_x509_extension(
							writer.next(),
							oid::CRL_INVALIDITY_DATE,
							false,
							|writer| {
								write_dt_utc_or_generalized(writer, invalidity_date);
							},
						)
					}
				});
			}
		})
	}
}
