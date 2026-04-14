use std::fmt;
use std::hash::{Hash, Hasher};

use yasna::models::ObjectIdentifier;
use yasna::DERWriter;
use yasna::Tag;

#[cfg(feature = "crypto")]
use crate::ring_like::signature::{self, EcdsaSigningAlgorithm, EdDSAParameters, RsaEncoding};
use crate::Error;

#[cfg(feature = "crypto")]
pub(crate) enum SignAlgo {
	EcDsa(&'static EcdsaSigningAlgorithm),
	EdDsa(&'static EdDSAParameters),
	Rsa(&'static dyn RsaEncoding),
}

#[derive(PartialEq, Eq, Hash)]
pub(crate) enum SignatureAlgorithmParams {
	/// Omit the parameters
	None,
	/// Write null parameters
	Null,
	/// RSASSA-PSS-params as per RFC 4055
	RsaPss {
		hash_algorithm: &'static [u64],
		salt_length: u64,
	},
}

/// Signature algorithm type
pub struct SignatureAlgorithm {
	oids_sign_alg: &'static [&'static [u64]],
	#[cfg(feature = "crypto")]
	pub(crate) sign_alg: SignAlgo,
	oid_components: &'static [u64],
	params: SignatureAlgorithmParams,
}

impl fmt::Debug for SignatureAlgorithm {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		use algo::*;
		if self == &PKCS_RSA_SHA256 {
			write!(f, "PKCS_RSA_SHA256")
		} else if self == &PKCS_RSA_SHA384 {
			write!(f, "PKCS_RSA_SHA384")
		} else if self == &PKCS_RSA_SHA512 {
			write!(f, "PKCS_RSA_SHA512")
		} else if self == &PKCS_RSA_PSS_SHA256 {
			write!(f, "PKCS_RSA_PSS_SHA256")
		} else if self == &PKCS_ECDSA_P256_SHA256 {
			write!(f, "PKCS_ECDSA_P256_SHA256")
		} else if self == &PKCS_ECDSA_P384_SHA384 {
			write!(f, "PKCS_ECDSA_P384_SHA384")
		} else if self == &PKCS_ED25519 {
			write!(f, "PKCS_ED25519")
		} else {
			#[cfg(feature = "aws_lc_rs")]
			if self == &PKCS_ECDSA_P521_SHA512 {
				return write!(f, "PKCS_ECDSA_P521_SHA512");
			}

			write!(f, "Unknown")
		}
	}
}

impl PartialEq for SignatureAlgorithm {
	fn eq(&self, other: &Self) -> bool {
		(self.oids_sign_alg, self.oid_components) == (other.oids_sign_alg, other.oid_components)
	}
}

impl Eq for SignatureAlgorithm {}

/// The `Hash` trait is not derived, but implemented according to impl of the `PartialEq` trait
impl Hash for SignatureAlgorithm {
	fn hash<H: Hasher>(&self, state: &mut H) {
		// see SignatureAlgorithm::eq(), just this field is compared
		self.oids_sign_alg.hash(state);
	}
}
impl SignatureAlgorithm {
	pub(crate) fn iter() -> std::slice::Iter<'static, &'static SignatureAlgorithm> {
		use algo::*;
		static ALGORITHMS: &[&SignatureAlgorithm] = &[
			&PKCS_RSA_SHA256,
			&PKCS_RSA_SHA384,
			&PKCS_RSA_SHA512,
			//&PKCS_RSA_PSS_SHA256,
			&PKCS_ECDSA_P256_SHA256,
			&PKCS_ECDSA_P384_SHA384,
			#[cfg(feature = "aws_lc_rs")]
			&PKCS_ECDSA_P521_SHA512,
			&PKCS_ED25519,
		];
		ALGORITHMS.iter()
	}

	/// Retrieve the SignatureAlgorithm for the provided OID
	pub fn from_oid(oid: &[u64]) -> Result<&'static SignatureAlgorithm, Error> {
		for algo in Self::iter() {
			if algo.oid_components == oid {
				return Ok(algo);
			}
		}
		Err(Error::UnsupportedSignatureAlgorithm)
	}
}

/// The list of supported signature algorithms
pub(crate) mod algo {
	use crate::oid::*;

	use super::*;

	/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&RSA_ENCRYPTION],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA256),
		// sha256WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 11],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&RSA_ENCRYPTION],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA384),
		// sha384WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 12],
		params: SignatureAlgorithmParams::Null,
	};

	/// RSA signing with PKCS#1 1.5 padding and SHA-512 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub static PKCS_RSA_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&RSA_ENCRYPTION],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PKCS1_SHA512),
		// sha512WithRSAEncryption in RFC 4055
		oid_components: &[1, 2, 840, 113549, 1, 1, 13],
		params: SignatureAlgorithmParams::Null,
	};

	// TODO: not really sure whether the certs we generate actually work.
	// Both openssl and webpki reject them. It *might* be possible that openssl
	// accepts the certificate if the key is a proper RSA-PSS key, but ring doesn't
	// support those: https://github.com/briansmith/ring/issues/1353
	//
	/// RSA signing with PKCS#1 2.1 RSASSA-PSS padding and SHA-256 hashing as per [RFC 4055](https://tools.ietf.org/html/rfc4055)
	pub(crate) static PKCS_RSA_PSS_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		// We could also use RSA_ENCRYPTION here, but it's recommended
		// to use ID-RSASSA-PSS if possible.
		oids_sign_alg: &[&RSASSA_PSS],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::Rsa(&signature::RSA_PSS_SHA256),
		oid_components: RSASSA_PSS, //&[1, 2, 840, 113549, 1, 1, 13],
		// rSASSA-PSS-SHA256-Params in RFC 4055
		params: SignatureAlgorithmParams::RsaPss {
			// id-sha256 in https://datatracker.ietf.org/doc/html/rfc4055#section-2.1
			hash_algorithm: &[2, 16, 840, 1, 101, 3, 4, 2, 1],
			salt_length: 20,
		},
	};

	/// ECDSA signing using the P-256 curves and SHA-256 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static PKCS_ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&EC_PUBLIC_KEY, &EC_SECP_256_R1],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
		// ecdsa-with-SHA256 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 2],
		params: SignatureAlgorithmParams::None,
	};

	/// ECDSA signing using the P-384 curves and SHA-384 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	pub static PKCS_ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&EC_PUBLIC_KEY, &EC_SECP_384_R1],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
		// ecdsa-with-SHA384 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 3],
		params: SignatureAlgorithmParams::None,
	};
	/// ECDSA signing using the P-521 curves and SHA-512 hashing as per [RFC 5758](https://tools.ietf.org/html/rfc5758#section-3.2)
	/// Currently this is only supported with the `aws_lc_rs` feature
	#[cfg(feature = "aws_lc_rs")]
	pub static PKCS_ECDSA_P521_SHA512: SignatureAlgorithm = SignatureAlgorithm {
		oids_sign_alg: &[&EC_PUBLIC_KEY, &EC_SECP_521_R1],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EcDsa(&signature::ECDSA_P521_SHA512_ASN1_SIGNING),
		// ecdsa-with-SHA512 in RFC 5758
		oid_components: &[1, 2, 840, 10045, 4, 3, 4],
		params: SignatureAlgorithmParams::None,
	};

	/// ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
	pub static PKCS_ED25519: SignatureAlgorithm = SignatureAlgorithm {
		// id-Ed25519 in RFC 8410
		oids_sign_alg: &[&[1, 3, 101, 112]],
		#[cfg(feature = "crypto")]
		sign_alg: SignAlgo::EdDsa(&signature::ED25519),
		// id-Ed25519 in RFC 8410
		oid_components: &[1, 3, 101, 112],
		params: SignatureAlgorithmParams::None,
	};
}
// Signature algorithm IDs as per https://tools.ietf.org/html/rfc4055
impl SignatureAlgorithm {
	fn alg_ident_oid(&self) -> ObjectIdentifier {
		ObjectIdentifier::from_slice(self.oid_components)
	}
	fn write_params(&self, writer: &mut yasna::DERWriterSeq) {
		match self.params {
			SignatureAlgorithmParams::None => (),
			SignatureAlgorithmParams::Null => {
				writer.next().write_null();
			},
			SignatureAlgorithmParams::RsaPss {
				hash_algorithm,
				salt_length,
			} => {
				writer.next().write_sequence(|writer| {
					// https://datatracker.ietf.org/doc/html/rfc4055#section-3.1

					let oid = ObjectIdentifier::from_slice(hash_algorithm);
					// hashAlgorithm
					writer.next().write_tagged(Tag::context(0), |writer| {
						writer.write_sequence(|writer| {
							writer.next().write_oid(&oid);
						});
					});
					// maskGenAlgorithm
					writer.next().write_tagged(Tag::context(1), |writer| {
						writer.write_sequence(|writer| {
							// id-mgf1 in RFC 4055
							const ID_MGF1: &[u64] = &[1, 2, 840, 113549, 1, 1, 8];
							let oid = ObjectIdentifier::from_slice(ID_MGF1);
							writer.next().write_oid(&oid);
							writer.next().write_sequence(|writer| {
								let oid = ObjectIdentifier::from_slice(hash_algorithm);
								writer.next().write_oid(&oid);
								writer.next().write_null();
							});
						});
					});
					// saltLength
					writer.next().write_tagged(Tag::context(2), |writer| {
						writer.write_u64(salt_length);
					});
					// We *must* omit the trailerField element as per RFC 4055 section 3.1
				})
			},
		}
	}
	/// Writes the algorithm identifier as it appears inside a signature
	pub(crate) fn write_alg_ident(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			writer.next().write_oid(&self.alg_ident_oid());
			self.write_params(writer);
		});
	}
	/// Writes the algorithm identifier as it appears inside subjectPublicKeyInfo
	pub(crate) fn write_oids_sign_alg(&self, writer: DERWriter) {
		writer.write_sequence(|writer| {
			for oid in self.oids_sign_alg {
				let oid = ObjectIdentifier::from_slice(oid);
				writer.next().write_oid(&oid);
			}
			self.write_params(writer);
		});
	}
}
