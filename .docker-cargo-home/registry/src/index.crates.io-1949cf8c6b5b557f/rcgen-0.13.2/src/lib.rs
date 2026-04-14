/*!
Rust X.509 certificate generation utility

This crate provides a way to generate self signed X.509 certificates.

The most simple way of using this crate is by calling the
[`generate_simple_self_signed`] function.
For more customization abilities, construct a [`CertificateParams`] and
a key pair to call [`CertificateParams::signed_by()`] or [`CertificateParams::self_signed()`].
*/
#![cfg_attr(
	feature = "pem",
	doc = r##"
## Example

```
use rcgen::{generate_simple_self_signed, CertifiedKey};
# fn main () {
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();
println!("{}", cert.pem());
println!("{}", key_pair.serialize_pem());
# }
```"##
)]
#![forbid(unsafe_code)]
#![forbid(non_ascii_idents)]
#![deny(missing_docs)]
#![allow(clippy::complexity, clippy::style, clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![warn(unreachable_pub)]

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
#[cfg(feature = "x509-parser")]
use std::net::{Ipv4Addr, Ipv6Addr};

use time::{OffsetDateTime, Time};
use yasna::models::ObjectIdentifier;
use yasna::models::{GeneralizedTime, UTCTime};
use yasna::tags::{TAG_BMPSTRING, TAG_TELETEXSTRING, TAG_UNIVERSALSTRING};
use yasna::DERWriter;
use yasna::Tag;

pub use certificate::{
	date_time_ymd, Attribute, BasicConstraints, Certificate, CertificateParams, CidrSubnet,
	CustomExtension, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, NameConstraints,
};
pub use crl::{
	CertificateRevocationList, CertificateRevocationListParams, CrlDistributionPoint,
	CrlIssuingDistributionPoint, CrlScope, RevocationReason, RevokedCertParams,
};
pub use csr::{CertificateSigningRequest, CertificateSigningRequestParams, PublicKey};
pub use error::{Error, InvalidAsn1String};
pub use key_pair::PublicKeyData;
#[cfg(all(feature = "crypto", feature = "aws_lc_rs"))]
pub use key_pair::RsaKeySize;
pub use key_pair::{KeyPair, RemoteKeyPair, SubjectPublicKeyInfo};
#[cfg(feature = "crypto")]
use ring_like::digest;
pub use sign_algo::algo::*;
pub use sign_algo::SignatureAlgorithm;
pub use string_types::*;

mod certificate;
mod crl;
mod csr;
mod error;
mod key_pair;
mod oid;
mod ring_like;
mod sign_algo;
mod string_types;

/// Type-alias for the old name of [`Error`].
#[deprecated(
	note = "Renamed to `Error`. We recommend to refer to it by fully-qualifying the crate: `rcgen::Error`."
)]
pub type RcgenError = Error;

/// An issued certificate, together with the subject keypair.
pub struct CertifiedKey {
	/// An issued certificate.
	pub cert: Certificate,
	/// The certificate's subject key pair.
	pub key_pair: KeyPair,
}

/**
KISS function to generate a self signed certificate

Given a set of domain names you want your certificate to be valid for,
this function fills in the other generation parameters with
reasonable defaults and generates a self signed certificate
and key pair as output.
*/
#[cfg(feature = "crypto")]
#[cfg_attr(
	feature = "pem",
	doc = r##"
## Example

```
use rcgen::{generate_simple_self_signed, CertifiedKey};
# fn main () {
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

// The certificate is now valid for localhost and the domain "hello.world.example"
println!("{}", cert.pem());
println!("{}", key_pair.serialize_pem());
# }
```
"##
)]
pub fn generate_simple_self_signed(
	subject_alt_names: impl Into<Vec<String>>,
) -> Result<CertifiedKey, Error> {
	let key_pair = KeyPair::generate()?;
	let cert = CertificateParams::new(subject_alt_names)?.self_signed(&key_pair)?;
	Ok(CertifiedKey { cert, key_pair })
}

struct Issuer<'a> {
	distinguished_name: &'a DistinguishedName,
	key_identifier_method: &'a KeyIdMethod,
	key_usages: &'a [KeyUsagePurpose],
	key_pair: &'a KeyPair,
}

// https://tools.ietf.org/html/rfc5280#section-4.1.1

// Example certs usable as reference:
// Uses ECDSA: https://crt.sh/?asn1=607203242

#[cfg(feature = "pem")]
const ENCODE_CONFIG: pem::EncodeConfig = {
	let line_ending = match cfg!(target_family = "windows") {
		true => pem::LineEnding::CRLF,
		false => pem::LineEnding::LF,
	};
	pem::EncodeConfig::new().set_line_ending(line_ending)
};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
#[non_exhaustive]
/// The type of subject alt name
pub enum SanType {
	/// Also known as E-Mail address
	Rfc822Name(Ia5String),
	DnsName(Ia5String),
	URI(Ia5String),
	IpAddress(IpAddr),
	OtherName((Vec<u64>, OtherNameValue)),
}

/// An `OtherName` value, defined in [RFC 5280§4.1.2.4].
///
/// While the standard specifies this could be any ASN.1 type rcgen limits
/// the value to a UTF-8 encoded string as this will cover the most common
/// use cases, for instance smart card user principal names (UPN).
///
/// [RFC 5280§4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum OtherNameValue {
	/// A string encoded using UTF-8
	Utf8String(String),
}

impl OtherNameValue {
	fn write_der(&self, writer: DERWriter) {
		writer.write_tagged(Tag::context(0), |writer| match self {
			OtherNameValue::Utf8String(s) => writer.write_utf8_string(s),
		});
	}
}

impl<T> From<T> for OtherNameValue
where
	T: Into<String>,
{
	fn from(t: T) -> Self {
		OtherNameValue::Utf8String(t.into())
	}
}

#[cfg(feature = "x509-parser")]
fn ip_addr_from_octets(octets: &[u8]) -> Result<IpAddr, Error> {
	if let Ok(ipv6_octets) = <&[u8; 16]>::try_from(octets) {
		Ok(Ipv6Addr::from(*ipv6_octets).into())
	} else if let Ok(ipv4_octets) = <&[u8; 4]>::try_from(octets) {
		Ok(Ipv4Addr::from(*ipv4_octets).into())
	} else {
		Err(Error::InvalidIpAddressOctetLength(octets.len()))
	}
}

impl SanType {
	#[cfg(feature = "x509-parser")]
	fn try_from_general(name: &x509_parser::extensions::GeneralName<'_>) -> Result<Self, Error> {
		use x509_parser::der_parser::asn1_rs::{self, FromDer, Tag, TaggedExplicit};
		Ok(match name {
			x509_parser::extensions::GeneralName::RFC822Name(name) => {
				SanType::Rfc822Name((*name).try_into()?)
			},
			x509_parser::extensions::GeneralName::DNSName(name) => {
				SanType::DnsName((*name).try_into()?)
			},
			x509_parser::extensions::GeneralName::URI(name) => SanType::URI((*name).try_into()?),
			x509_parser::extensions::GeneralName::IPAddress(octets) => {
				SanType::IpAddress(ip_addr_from_octets(octets)?)
			},
			x509_parser::extensions::GeneralName::OtherName(oid, value) => {
				let oid = oid.iter().ok_or(Error::CouldNotParseCertificate)?;
				// We first remove the explicit tag ([0] EXPLICIT)
				let (_, other_name) = TaggedExplicit::<asn1_rs::Any, _, 0>::from_der(value)
					.map_err(|_| Error::CouldNotParseCertificate)?;
				let other_name = other_name.into_inner();

				let other_name_value = match other_name.tag() {
					Tag::Utf8String => OtherNameValue::Utf8String(
						std::str::from_utf8(other_name.data)
							.map_err(|_| Error::CouldNotParseCertificate)?
							.to_owned(),
					),
					_ => return Err(Error::CouldNotParseCertificate),
				};
				SanType::OtherName((oid.collect(), other_name_value))
			},
			_ => return Err(Error::InvalidNameType),
		})
	}

	fn tag(&self) -> u64 {
		// Defined in the GeneralName list in
		// https://tools.ietf.org/html/rfc5280#page-38
		const TAG_OTHER_NAME: u64 = 0;
		const TAG_RFC822_NAME: u64 = 1;
		const TAG_DNS_NAME: u64 = 2;
		const TAG_URI: u64 = 6;
		const TAG_IP_ADDRESS: u64 = 7;

		match self {
			SanType::Rfc822Name(_name) => TAG_RFC822_NAME,
			SanType::DnsName(_name) => TAG_DNS_NAME,
			SanType::URI(_name) => TAG_URI,
			SanType::IpAddress(_addr) => TAG_IP_ADDRESS,
			Self::OtherName(_oid) => TAG_OTHER_NAME,
		}
	}
}

/// A distinguished name entry
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum DnValue {
	/// A string encoded using UCS-2
	BmpString(BmpString),
	/// An ASCII string.
	Ia5String(Ia5String),
	/// An ASCII string containing only A-Z, a-z, 0-9, '()+,-./:=? and `<SPACE>`
	PrintableString(PrintableString),
	/// A string of characters from the T.61 character set
	TeletexString(TeletexString),
	/// A string encoded using UTF-32
	UniversalString(UniversalString),
	/// A string encoded using UTF-8
	Utf8String(String),
}

impl<T> From<T> for DnValue
where
	T: Into<String>,
{
	fn from(t: T) -> Self {
		DnValue::Utf8String(t.into())
	}
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
/**
Distinguished name used e.g. for the issuer and subject fields of a certificate

A distinguished name is a set of (attribute type, attribute value) tuples.

This datastructure keeps them ordered by insertion order.

See also the RFC 5280 sections on the [issuer](https://tools.ietf.org/html/rfc5280#section-4.1.2.4)
and [subject](https://tools.ietf.org/html/rfc5280#section-4.1.2.6) fields.
*/
pub struct DistinguishedName {
	entries: HashMap<DnType, DnValue>,
	order: Vec<DnType>,
}

impl DistinguishedName {
	/// Creates a new, empty distinguished name
	pub fn new() -> Self {
		Self::default()
	}
	/// Obtains the attribute value for the given attribute type
	pub fn get(&self, ty: &DnType) -> Option<&DnValue> {
		self.entries.get(ty)
	}
	/// Removes the attribute with the specified DnType
	///
	/// Returns true when an actual removal happened, false
	/// when no attribute with the specified DnType was
	/// found.
	pub fn remove(&mut self, ty: DnType) -> bool {
		let removed = self.entries.remove(&ty).is_some();
		if removed {
			self.order.retain(|ty_o| &ty != ty_o);
		}
		removed
	}
	/// Inserts or updates an attribute that consists of type and name
	///
	/// ```
	/// # use rcgen::{DistinguishedName, DnType, DnValue};
	/// let mut dn = DistinguishedName::new();
	/// dn.push(DnType::OrganizationName, "Crab widgits SE");
	/// dn.push(DnType::CommonName, DnValue::PrintableString("Master Cert".try_into().unwrap()));
	/// assert_eq!(dn.get(&DnType::OrganizationName), Some(&DnValue::Utf8String("Crab widgits SE".to_string())));
	/// assert_eq!(dn.get(&DnType::CommonName), Some(&DnValue::PrintableString("Master Cert".try_into().unwrap())));
	/// ```
	pub fn push(&mut self, ty: DnType, s: impl Into<DnValue>) {
		if !self.entries.contains_key(&ty) {
			self.order.push(ty.clone());
		}
		self.entries.insert(ty, s.into());
	}
	/// Iterate over the entries
	pub fn iter(&self) -> DistinguishedNameIterator<'_> {
		DistinguishedNameIterator {
			distinguished_name: self,
			iter: self.order.iter(),
		}
	}

	#[cfg(feature = "x509-parser")]
	fn from_name(name: &x509_parser::x509::X509Name) -> Result<Self, Error> {
		use x509_parser::der_parser::asn1_rs::Tag;

		let mut dn = DistinguishedName::new();
		for rdn in name.iter() {
			let mut rdn_iter = rdn.iter();
			let dn_opt = rdn_iter.next();
			let attr = if let Some(dn) = dn_opt {
				if rdn_iter.next().is_some() {
					// no support for distinguished names with more than one attribute
					return Err(Error::CouldNotParseCertificate);
				} else {
					dn
				}
			} else {
				panic!("x509-parser distinguished name set is empty");
			};

			let attr_type_oid = attr
				.attr_type()
				.iter()
				.ok_or(Error::CouldNotParseCertificate)?;
			let dn_type = DnType::from_oid(&attr_type_oid.collect::<Vec<_>>());
			let data = attr.attr_value().data;
			let try_str =
				|data| std::str::from_utf8(data).map_err(|_| Error::CouldNotParseCertificate);
			let dn_value = match attr.attr_value().header.tag() {
				Tag::BmpString => DnValue::BmpString(BmpString::from_utf16be(data.to_vec())?),
				Tag::Ia5String => DnValue::Ia5String(try_str(data)?.try_into()?),
				Tag::PrintableString => DnValue::PrintableString(try_str(data)?.try_into()?),
				Tag::T61String => DnValue::TeletexString(try_str(data)?.try_into()?),
				Tag::UniversalString => {
					DnValue::UniversalString(UniversalString::from_utf32be(data.to_vec())?)
				},
				Tag::Utf8String => DnValue::Utf8String(try_str(data)?.to_owned()),
				_ => return Err(Error::CouldNotParseCertificate),
			};

			dn.push(dn_type, dn_value);
		}
		Ok(dn)
	}
}

/**
Iterator over [`DistinguishedName`] entries
*/
pub struct DistinguishedNameIterator<'a> {
	distinguished_name: &'a DistinguishedName,
	iter: std::slice::Iter<'a, DnType>,
}

impl<'a> Iterator for DistinguishedNameIterator<'a> {
	type Item = (&'a DnType, &'a DnValue);

	fn next(&mut self) -> Option<Self::Item> {
		self.iter
			.next()
			.and_then(|ty| self.distinguished_name.entries.get(ty).map(|v| (ty, v)))
	}
}

/// One of the purposes contained in the [key usage](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) extension
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum KeyUsagePurpose {
	/// digitalSignature
	DigitalSignature,
	/// contentCommitment / nonRepudiation
	ContentCommitment,
	/// keyEncipherment
	KeyEncipherment,
	/// dataEncipherment
	DataEncipherment,
	/// keyAgreement
	KeyAgreement,
	/// keyCertSign
	KeyCertSign,
	/// cRLSign
	CrlSign,
	/// encipherOnly
	EncipherOnly,
	/// decipherOnly
	DecipherOnly,
}

impl KeyUsagePurpose {
	/// Encode a key usage as the value of a BIT STRING as defined by RFC 5280.
	/// [`u16`] is sufficient to encode the largest possible key usage value (two bytes).
	fn to_u16(&self) -> u16 {
		const FLAG: u16 = 0b1000_0000_0000_0000;
		FLAG >> match self {
			KeyUsagePurpose::DigitalSignature => 0,
			KeyUsagePurpose::ContentCommitment => 1,
			KeyUsagePurpose::KeyEncipherment => 2,
			KeyUsagePurpose::DataEncipherment => 3,
			KeyUsagePurpose::KeyAgreement => 4,
			KeyUsagePurpose::KeyCertSign => 5,
			KeyUsagePurpose::CrlSign => 6,
			KeyUsagePurpose::EncipherOnly => 7,
			KeyUsagePurpose::DecipherOnly => 8,
		}
	}

	/// Parse a collection of key usages from a [`u16`] representing the value
	/// of a KeyUsage BIT STRING as defined by RFC 5280.
	#[cfg(feature = "x509-parser")]
	fn from_u16(value: u16) -> Vec<Self> {
		[
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::DataEncipherment,
			KeyUsagePurpose::KeyAgreement,
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			KeyUsagePurpose::EncipherOnly,
			KeyUsagePurpose::DecipherOnly,
		]
		.iter()
		.filter_map(|key_usage| {
			let present = key_usage.to_u16() & value != 0;
			present.then_some(*key_usage)
		})
		.collect()
	}
}

/// Method to generate key identifiers from public keys.
///
/// Key identifiers should be derived from the public key data. [RFC 7093] defines
/// three methods to do so using a choice of SHA256 (method 1), SHA384 (method 2), or SHA512
/// (method 3). In each case the first 160 bits of the hash are used as the key identifier
/// to match the output length that would be produced were SHA1 used (a legacy option defined
/// in RFC 5280).
///
/// In addition to the RFC 7093 mechanisms, rcgen supports using a pre-specified key identifier.
/// This can be helpful when working with an existing `Certificate`.
///
/// [RFC 7093]: https://www.rfc-editor.org/rfc/rfc7093
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[non_exhaustive]
pub enum KeyIdMethod {
	/// RFC 7093 method 1 - a truncated SHA256 digest.
	#[cfg(feature = "crypto")]
	Sha256,
	/// RFC 7093 method 2 - a truncated SHA384 digest.
	#[cfg(feature = "crypto")]
	Sha384,
	/// RFC 7093 method 3 - a truncated SHA512 digest.
	#[cfg(feature = "crypto")]
	Sha512,
	/// Pre-specified identifier. The exact given value is used as the key identifier.
	PreSpecified(Vec<u8>),
}

impl KeyIdMethod {
	/// Derive a key identifier for the provided subject public key info using the key ID method.
	///
	/// Typically this is a truncated hash over the raw subject public key info, but may
	/// be a pre-specified value.
	///
	/// This key identifier is used in the SubjectKeyIdentifier and AuthorityKeyIdentifier
	/// X.509v3 extensions.
	#[allow(unused_variables)]
	pub(crate) fn derive(&self, subject_public_key_info: impl AsRef<[u8]>) -> Vec<u8> {
		let digest_method = match &self {
			#[cfg(feature = "crypto")]
			Self::Sha256 => &digest::SHA256,
			#[cfg(feature = "crypto")]
			Self::Sha384 => &digest::SHA384,
			#[cfg(feature = "crypto")]
			Self::Sha512 => &digest::SHA512,
			Self::PreSpecified(b) => {
				return b.to_vec();
			},
		};
		#[cfg(feature = "crypto")]
		{
			let digest = digest::digest(digest_method, subject_public_key_info.as_ref());
			digest.as_ref()[0..20].to_vec()
		}
	}
}

fn dt_strip_nanos(dt: OffsetDateTime) -> OffsetDateTime {
	// Set nanoseconds to zero
	// This is needed because the GeneralizedTime serializer would otherwise
	// output fractional values which RFC 5280 explicitly forbode [1].
	// UTCTime cannot express fractional seconds or leap seconds
	// therefore, it needs to be stripped of nanoseconds fully.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
	// TODO: handle leap seconds if dt becomes leap second aware
	let time =
		Time::from_hms(dt.hour(), dt.minute(), dt.second()).expect("invalid or out-of-range time");
	dt.replace_time(time)
}

fn dt_to_generalized(dt: OffsetDateTime) -> GeneralizedTime {
	let date_time = dt_strip_nanos(dt);
	GeneralizedTime::from_datetime(date_time)
}

fn write_dt_utc_or_generalized(writer: DERWriter, dt: OffsetDateTime) {
	// RFC 5280 requires CAs to write certificate validity dates
	// below 2050 as UTCTime, and anything starting from 2050
	// as GeneralizedTime [1]. The RFC doesn't say anything
	// about dates before 1950, but as UTCTime can't represent
	// them, we have to use GeneralizedTime if we want to or not.
	// [1]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
	if (1950..2050).contains(&dt.year()) {
		let date_time = dt_strip_nanos(dt);
		let ut = UTCTime::from_datetime(date_time);
		writer.write_utctime(&ut);
	} else {
		let gt = dt_to_generalized(dt);
		writer.write_generalized_time(&gt);
	}
}

fn write_distinguished_name(writer: DERWriter, dn: &DistinguishedName) {
	writer.write_sequence(|writer| {
		for (ty, content) in dn.iter() {
			writer.next().write_set(|writer| {
				writer.next().write_sequence(|writer| {
					writer.next().write_oid(&ty.to_oid());
					match content {
						DnValue::BmpString(s) => writer
							.next()
							.write_tagged_implicit(TAG_BMPSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),

						DnValue::Ia5String(s) => writer.next().write_ia5_string(s.as_str()),

						DnValue::PrintableString(s) => {
							writer.next().write_printable_string(s.as_str())
						},
						DnValue::TeletexString(s) => writer
							.next()
							.write_tagged_implicit(TAG_TELETEXSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),
						DnValue::UniversalString(s) => writer
							.next()
							.write_tagged_implicit(TAG_UNIVERSALSTRING, |writer| {
								writer.write_bytes(s.as_bytes())
							}),
						DnValue::Utf8String(s) => writer.next().write_utf8_string(s),
					}
				});
			});
		}
	});
}

/// Serializes an X.509v3 extension according to RFC 5280
fn write_x509_extension(
	writer: DERWriter,
	extension_oid: &[u64],
	is_critical: bool,
	value_serializer: impl FnOnce(DERWriter),
) {
	// Extension specification:
	//    Extension  ::=  SEQUENCE  {
	//         extnID      OBJECT IDENTIFIER,
	//         critical    BOOLEAN DEFAULT FALSE,
	//         extnValue   OCTET STRING
	//                     -- contains the DER encoding of an ASN.1 value
	//                     -- corresponding to the extension type identified
	//                     -- by extnID
	//         }

	writer.write_sequence(|writer| {
		let oid = ObjectIdentifier::from_slice(extension_oid);
		writer.next().write_oid(&oid);
		if is_critical {
			writer.next().write_bool(true);
		}
		let bytes = yasna::construct_der(value_serializer);
		writer.next().write_bytes(&bytes);
	})
}

/// Serializes an X.509v3 authority key identifier extension according to RFC 5280.
fn write_x509_authority_key_identifier(writer: DERWriter, aki: Vec<u8>) {
	// Write Authority Key Identifier
	// RFC 5280 states:
	//   'The keyIdentifier field of the authorityKeyIdentifier extension MUST
	//    be included in all certificates generated by conforming CAs to
	//    facilitate certification path construction.  There is one exception;
	//    where a CA distributes its public key in the form of a "self-signed"
	//    certificate, the authority key identifier MAY be omitted.'
	// In addition, for CRLs:
	//    'Conforming CRL issuers MUST use the key identifier method, and MUST
	//     include this extension in all CRLs issued.'
	write_x509_extension(writer, oid::AUTHORITY_KEY_IDENTIFIER, false, |writer| {
		writer.write_sequence(|writer| {
			writer
				.next()
				.write_tagged_implicit(Tag::context(0), |writer| writer.write_bytes(&aki))
		});
	});
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for KeyPair {
	fn zeroize(&mut self) {
		self.serialized_der.zeroize();
	}
}

/// A certificate serial number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SerialNumber {
	inner: Vec<u8>,
}

impl SerialNumber {
	/// Create a serial number from the given byte slice.
	pub fn from_slice(bytes: &[u8]) -> SerialNumber {
		let inner = bytes.to_vec();
		SerialNumber { inner }
	}

	/// Return the byte representation of the serial number.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.inner.clone()
	}

	/// Return the length of the serial number in bytes.
	pub fn len(&self) -> usize {
		self.inner.len()
	}
}

impl fmt::Display for SerialNumber {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		let hex: Vec<_> = self.inner.iter().map(|b| format!("{:02x}", b)).collect();
		write!(f, "{}", hex.join(":"))
	}
}

impl From<Vec<u8>> for SerialNumber {
	fn from(inner: Vec<u8>) -> SerialNumber {
		SerialNumber { inner }
	}
}

impl From<u64> for SerialNumber {
	fn from(u: u64) -> SerialNumber {
		let inner = u.to_be_bytes().into();
		SerialNumber { inner }
	}
}

impl AsRef<[u8]> for SerialNumber {
	fn as_ref(&self) -> &[u8] {
		&self.inner
	}
}

#[cfg(test)]
mod tests {
	use std::panic::catch_unwind;

	use time::{Date, Month, PrimitiveDateTime};

	use super::*;

	fn times() -> [OffsetDateTime; 2] {
		let dt_nanos = {
			let date = Date::from_calendar_date(2020, Month::December, 3).unwrap();
			let time = Time::from_hms_nano(0, 0, 1, 444).unwrap();
			PrimitiveDateTime::new(date, time).assume_utc()
		};
		let dt_zero = {
			let date = Date::from_calendar_date(2020, Month::December, 3).unwrap();
			let time = Time::from_hms_nano(0, 0, 1, 0).unwrap();
			PrimitiveDateTime::new(date, time).assume_utc()
		};
		// TODO: include leap seconds if time becomes leap second aware
		[dt_nanos, dt_zero]
	}

	#[test]
	fn test_dt_utc_strip_nanos() {
		let times = times();

		// No stripping - OffsetDateTime with nanos
		let res = catch_unwind(|| UTCTime::from_datetime(times[0]));
		assert!(res.is_err());

		// Stripping
		for dt in times {
			let date_time = dt_strip_nanos(dt);
			assert_eq!(date_time.time().nanosecond(), 0);
			let _ut = UTCTime::from_datetime(date_time);
		}
	}

	#[test]
	fn test_dt_to_generalized() {
		let times = times();

		for dt in times {
			let _gt = dt_to_generalized(dt);
		}
	}

	#[test]
	fn signature_algos_different() {
		// TODO unify this with test_key_params_mismatch.
		// Note that that test doesn't have a full list of signature
		// algorithms, as it has no access to the iter function.
		for (i, alg_i) in SignatureAlgorithm::iter().enumerate() {
			for (j, alg_j) in SignatureAlgorithm::iter().enumerate() {
				assert_eq!(
					alg_i == alg_j,
					i == j,
					"Algorighm relationship mismatch for algorithm index pair {} and {}",
					i,
					j
				);
			}
		}
	}

	#[cfg(feature = "x509-parser")]
	mod test_ip_address_from_octets {
		use super::super::ip_addr_from_octets;
		use super::super::Error;
		use std::net::IpAddr;

		#[test]
		fn ipv4() {
			let octets = [10, 20, 30, 40];

			let actual = ip_addr_from_octets(&octets).unwrap();

			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn ipv6() {
			let octets = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

			let actual = ip_addr_from_octets(&octets).unwrap();

			assert_eq!(IpAddr::from(octets), actual)
		}

		#[test]
		fn mismatch() {
			let incorrect = Vec::from_iter(0..10);
			let actual = ip_addr_from_octets(&incorrect).unwrap_err();

			assert_eq!(Error::InvalidIpAddressOctetLength(10), actual);
		}

		#[test]
		fn none() {
			let actual = ip_addr_from_octets(&[]).unwrap_err();

			assert_eq!(Error::InvalidIpAddressOctetLength(0), actual);
		}

		#[test]
		fn too_many() {
			let incorrect = Vec::from_iter(0..20);
			let actual = ip_addr_from_octets(&incorrect).unwrap_err();

			assert_eq!(Error::InvalidIpAddressOctetLength(20), actual);
		}
	}

	#[cfg(feature = "x509-parser")]
	mod test_san_type_from_general_name {
		use crate::SanType;
		use std::net::IpAddr;
		use x509_parser::extensions::GeneralName;

		#[test]
		fn with_ipv4() {
			let octets = [1, 2, 3, 4];
			let value = GeneralName::IPAddress(&octets);
			let actual = SanType::try_from_general(&value).unwrap();

			assert_eq!(SanType::IpAddress(IpAddr::from(octets)), actual);
		}
	}
}
