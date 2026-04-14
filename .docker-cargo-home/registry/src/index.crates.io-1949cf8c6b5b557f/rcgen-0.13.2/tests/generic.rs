#![cfg(feature = "crypto")]

mod util;

#[cfg(feature = "pem")]
mod test_key_params_mismatch {
	use std::collections::hash_map::DefaultHasher;
	use std::hash::{Hash, Hasher};

	fn generate_hash<T: Hash>(subject: &T) -> u64 {
		let mut hasher = DefaultHasher::new();
		subject.hash(&mut hasher);
		hasher.finish()
	}

	#[test]
	fn test_key_params_mismatch() {
		let available_key_params = [
			&rcgen::PKCS_RSA_SHA256,
			&rcgen::PKCS_ECDSA_P256_SHA256,
			&rcgen::PKCS_ECDSA_P384_SHA384,
			#[cfg(feature = "aws_lc_rs")]
			&rcgen::PKCS_ECDSA_P521_SHA512,
			&rcgen::PKCS_ED25519,
		];
		for (i, kalg_1) in available_key_params.iter().enumerate() {
			for (j, kalg_2) in available_key_params.iter().enumerate() {
				if i == j {
					assert_eq!(*kalg_1, *kalg_2);
					assert_eq!(generate_hash(*kalg_1), generate_hash(*kalg_2));
					continue;
				}

				assert_ne!(*kalg_1, *kalg_2);
				assert_ne!(generate_hash(*kalg_1), generate_hash(*kalg_2));
			}
		}
	}
}

#[cfg(feature = "x509-parser")]
mod test_convert_x509_subject_alternative_name {
	use rcgen::{BasicConstraints, CertificateParams, IsCa, SanType};
	use std::net::{IpAddr, Ipv4Addr};

	#[test]
	fn converts_from_ip() {
		let ip = Ipv4Addr::new(2, 4, 6, 8);
		let ip_san = SanType::IpAddress(IpAddr::V4(ip));

		let (mut params, ca_key) = super::util::default_params();

		// Add the SAN we want to test the parsing for
		params.subject_alt_names.push(ip_san.clone());

		// Because we're using a function for CA certificates
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

		let cert = params.self_signed(&ca_key).unwrap();

		// Serialize our cert that has our chosen san, so we can testing parsing/deserializing it.
		let ca_der = cert.der();

		let actual = CertificateParams::from_ca_cert_der(ca_der).unwrap();
		assert!(actual.subject_alt_names.contains(&ip_san));
	}
}

#[cfg(feature = "x509-parser")]
mod test_x509_custom_ext {
	use crate::util;

	use rcgen::CustomExtension;
	use x509_parser::oid_registry::asn1_rs;
	use x509_parser::prelude::{
		FromDer, ParsedCriAttribute, X509Certificate, X509CertificationRequest,
	};

	#[test]
	fn custom_ext() {
		// Create an imaginary critical custom extension for testing.
		let test_oid = asn1_rs::Oid::from(&[2, 5, 29, 999999]).unwrap();
		let test_ext = yasna::construct_der(|writer| {
			writer.write_utf8_string("🦀 greetz to ferris 🦀");
		});
		let mut custom_ext = CustomExtension::from_oid_content(
			test_oid.iter().unwrap().collect::<Vec<u64>>().as_slice(),
			test_ext.clone(),
		);
		custom_ext.set_criticality(true);

		// Generate a certificate with the custom extension, parse it with x509-parser.
		let (mut params, test_key) = util::default_params();
		params.custom_extensions = vec![custom_ext];
		// Ensure the custom exts. being omitted into a CSR doesn't require SAN ext being present.
		// See https://github.com/rustls/rcgen/issues/122
		params.subject_alt_names = Vec::default();
		let test_cert = params.self_signed(&test_key).unwrap();
		let (_, x509_test_cert) = X509Certificate::from_der(test_cert.der()).unwrap();

		// We should be able to find the extension by OID, with expected criticality and value.
		let favorite_drink_ext = x509_test_cert
			.get_extension_unique(&test_oid)
			.expect("invalid extensions")
			.expect("missing custom extension");
		assert!(favorite_drink_ext.critical);
		assert_eq!(favorite_drink_ext.value, test_ext);

		// Generate a CSR with the custom extension, parse it with x509-parser.
		let test_cert_csr = test_cert.params().serialize_request(&test_key).unwrap();
		let (_, x509_csr) = X509CertificationRequest::from_der(test_cert_csr.der()).unwrap();

		// We should find that the CSR contains requested extensions.
		// Note: we can't use `x509_csr.requested_extensions()` here because it maps the raw extension
		// request extensions to their parsed form, and of course x509-parser doesn't parse our custom extension.
		let exts = x509_csr
			.certification_request_info
			.iter_attributes()
			.find_map(|attr| {
				if let ParsedCriAttribute::ExtensionRequest(requested) = &attr.parsed_attribute() {
					Some(requested.extensions.iter().collect::<Vec<_>>())
				} else {
					None
				}
			})
			.expect("missing requested extensions");

		// We should find the custom extension with expected criticality and value.
		let custom_ext = exts
			.iter()
			.find(|ext| ext.oid == test_oid)
			.expect("missing requested custom extension");
		assert!(custom_ext.critical);
		assert_eq!(custom_ext.value, test_ext);
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_custom_attributes {
	use rcgen::{Attribute, CertificateParams, KeyPair};
	use x509_parser::{
		der_parser::Oid,
		prelude::{FromDer, X509CertificationRequest},
	};

	/// Test serializing a CSR with custom attributes.
	/// This test case uses `challengePassword` from [RFC 2985], a simple
	/// ATTRIBUTE that contains a single UTF8String.
	///
	/// [RFC 2985]: <https://datatracker.ietf.org/doc/html/rfc2985>
	#[test]
	fn test_csr_custom_attributes() {
		// OID for challengePassword
		const CHALLENGE_PWD_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 7];

		// Attribute values for challengePassword
		let challenge_pwd_values = yasna::try_construct_der::<_, ()>(|writer| {
			// Reminder: CSR attribute values are contained in a SET
			writer.write_set(|writer| {
				// Challenge passwords only have one value, a UTF8String
				writer
					.next()
					.write_utf8_string("nobody uses challenge passwords anymore");
				Ok(())
			})
		})
		.unwrap();

		// Challenge password attribute
		let challenge_password_attribute = Attribute {
			oid: CHALLENGE_PWD_OID,
			values: challenge_pwd_values.clone(),
		};

		// Serialize a DER-encoded CSR
		let params = CertificateParams::default();
		let key_pair = KeyPair::generate().unwrap();
		let csr = params
			.serialize_request_with_attributes(&key_pair, vec![challenge_password_attribute])
			.unwrap();

		// Parse the CSR
		let (_, x509_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let parsed_attribute_value = x509_csr
			.certification_request_info
			.attributes_map()
			.unwrap()
			.get(&Oid::from(CHALLENGE_PWD_OID).unwrap())
			.unwrap()
			.value;
		assert_eq!(parsed_attribute_value, challenge_pwd_values);
	}
}

#[cfg(feature = "x509-parser")]
mod test_x509_parser_crl {
	use crate::util;
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};
	use x509_parser::num_bigint::BigUint;
	use x509_parser::prelude::{FromDer, GeneralName, IssuingDistributionPoint, X509Certificate};
	use x509_parser::revocation_list::CertificateRevocationList;
	use x509_parser::x509::X509Version;

	#[test]
	fn parse_crl() {
		// Create a CRL with one revoked cert, and an issuer to sign the CRL.
		let (crl, issuer) = util::test_crl();
		let revoked_cert = crl.params().revoked_certs.first().unwrap();
		let revoked_cert_serial = BigUint::from_bytes_be(revoked_cert.serial_number.as_ref());
		let (_, x509_issuer) = X509Certificate::from_der(issuer.der()).unwrap();

		// We should be able to parse the CRL with x509-parser without error.
		let (_, x509_crl) =
			CertificateRevocationList::from_der(crl.der()).expect("failed to parse CRL DER");

		// The properties of the CRL should match expected.
		assert_eq!(x509_crl.version().unwrap(), X509Version(1));
		assert_eq!(x509_crl.issuer(), x509_issuer.subject());
		assert_eq!(
			x509_crl.last_update().to_datetime().unix_timestamp(),
			crl.params().this_update.unix_timestamp()
		);
		assert_eq!(
			x509_crl
				.next_update()
				.unwrap()
				.to_datetime()
				.unix_timestamp(),
			crl.params().next_update.unix_timestamp()
		);
		let crl_number = BigUint::from_bytes_be(crl.params().crl_number.as_ref());
		assert_eq!(x509_crl.crl_number().unwrap(), &crl_number);

		// We should find the expected revoked certificate serial with the correct reason code.
		let x509_revoked_cert = x509_crl
			.iter_revoked_certificates()
			.next()
			.expect("failed to find revoked cert in CRL");
		assert_eq!(x509_revoked_cert.user_certificate, revoked_cert_serial);
		let (_, reason_code) = x509_revoked_cert.reason_code().unwrap();
		assert_eq!(reason_code.0, revoked_cert.reason_code.unwrap() as u8);

		// The issuing distribution point extension should be present and marked critical.
		let issuing_dp_ext = x509_crl
			.extensions()
			.iter()
			.find(|ext| {
				ext.oid == x509_parser::oid_registry::OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
			})
			.expect("failed to find issuing distribution point extension");
		assert!(issuing_dp_ext.critical);

		// The parsed issuing distribution point extension should match expected.
		let ParsedExtension::IssuingDistributionPoint(idp) = issuing_dp_ext.parsed_extension()
		else {
			panic!("missing parsed CRL IDP ext");
		};
		assert_eq!(
			idp,
			&IssuingDistributionPoint {
				only_contains_user_certs: true,
				only_contains_ca_certs: false,
				only_contains_attribute_certs: false,
				indirect_crl: false,
				only_some_reasons: None,
				distribution_point: Some(DistributionPointName::FullName(vec![GeneralName::URI(
					"http://example.com/crl",
				)])),
			}
		);

		// We should be able to verify the CRL signature with the issuer.
		assert!(x509_crl.verify_signature(x509_issuer.public_key()).is_ok());
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_crl_dps {
	use crate::util;
	use x509_parser::extensions::{DistributionPointName, ParsedExtension};

	#[test]
	fn parse_crl_dps() {
		// Generate and parse a certificate that includes two CRL distribution points.
		let der = util::cert_with_crl_dps();
		let (_, parsed_cert) = x509_parser::parse_x509_certificate(&der).unwrap();

		// We should find a CRL DP extension was parsed.
		let crl_dps = parsed_cert
			.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
			.expect("malformed CRL distribution points extension")
			.expect("missing CRL distribution points extension");

		// The extension should not be critical.
		assert!(!crl_dps.critical);

		// We should be able to parse the definition.
		let crl_dps = match crl_dps.parsed_extension() {
			ParsedExtension::CRLDistributionPoints(crl_dps) => crl_dps,
			_ => panic!("unexpected parsed extension type"),
		};

		// There should be two DPs.
		assert_eq!(crl_dps.points.len(), 2);

		// Each distribution point should only include a distribution point name holding a sequence
		// of general names.
		let general_names = crl_dps
			.points
			.iter()
			.flat_map(|dp| {
				// We shouldn't find a cRLIssuer or onlySomeReasons field.
				assert!(dp.crl_issuer.is_none());
				assert!(dp.reasons.is_none());

				match dp
					.distribution_point
					.as_ref()
					.expect("missing distribution point name")
				{
					DistributionPointName::FullName(general_names) => general_names.iter(),
					DistributionPointName::NameRelativeToCRLIssuer(_) => {
						panic!("unexpected name relative to cRL issuer")
					},
				}
			})
			.collect::<Vec<_>>();

		// All of the general names should be URIs.
		let uris = general_names
			.iter()
			.map(|general_name| match general_name {
				x509_parser::extensions::GeneralName::URI(uri) => *uri,
				_ => panic!("unexpected general name type"),
			})
			.collect::<Vec<_>>();

		// We should find the expected URIs.
		assert_eq!(
			uris,
			&[
				"http://example.com/crl.der",
				"http://crls.example.com/1234",
				"ldap://example.com/crl.der"
			]
		);
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_ia5string_subject {
	use crate::util;
	use rcgen::DnType::CustomDnType;
	use rcgen::{CertificateParams, DistinguishedName, DnValue};

	#[test]
	fn parse_ia5string_subject() {
		// Create and serialize a certificate with a subject containing an IA5String email address.
		let email_address_dn_type = CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]); // id-emailAddress
		let email_address_dn_value = DnValue::Ia5String("foo@bar.com".try_into().unwrap());
		let (mut params, key_pair) = util::default_params();
		params.distinguished_name = DistinguishedName::new();
		params.distinguished_name.push(
			email_address_dn_type.clone(),
			email_address_dn_value.clone(),
		);
		let cert = params.self_signed(&key_pair).unwrap();
		let cert_der = cert.der();

		// We should be able to parse the certificate with x509-parser.
		assert!(x509_parser::parse_x509_certificate(cert_der).is_ok());

		// We should be able to reconstitute params from the DER using x509-parser.
		let params_from_cert = CertificateParams::from_ca_cert_der(cert_der).unwrap();

		// We should find the expected distinguished name in the reconstituted params.
		let expected_names = &[(&email_address_dn_type, &email_address_dn_value)];
		let names = params_from_cert
			.distinguished_name
			.iter()
			.collect::<Vec<(_, _)>>();
		assert_eq!(names, expected_names);
	}
}

#[cfg(feature = "x509-parser")]
mod test_parse_other_name_alt_name {
	use rcgen::{CertificateParams, KeyPair, SanType};

	#[test]
	fn parse_other_name_alt_name() {
		// Create and serialize a certificate with an alternative name containing an "OtherName".
		let mut params = CertificateParams::default();
		let other_name = SanType::OtherName((vec![1, 2, 3, 4], "Foo".into()));
		params.subject_alt_names.push(other_name.clone());
		let key_pair = KeyPair::generate().unwrap();

		let cert = params.self_signed(&key_pair).unwrap();

		let cert_der = cert.der();

		// We should be able to parse the certificate with x509-parser.
		assert!(x509_parser::parse_x509_certificate(cert_der).is_ok());

		// We should be able to reconstitute params from the DER using x509-parser.
		let params_from_cert = CertificateParams::from_ca_cert_der(cert_der).unwrap();

		// We should find the expected distinguished name in the reconstituted params.
		let expected_alt_names = &[&other_name];
		let subject_alt_names = params_from_cert
			.subject_alt_names
			.iter()
			.collect::<Vec<_>>();
		assert_eq!(subject_alt_names, expected_alt_names);
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr_extension_request {
	use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
	use x509_parser::prelude::{FromDer, ParsedExtension, X509CertificationRequest};

	#[test]
	fn dont_write_sans_extension_if_no_sans_are_present() {
		let mut params = CertificateParams::default();
		params.key_usages.push(KeyUsagePurpose::DigitalSignature);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		assert!(!parsed_csr
			.requested_extensions()
			.unwrap()
			.any(|ext| matches!(ext, ParsedExtension::SubjectAlternativeName(_))));
	}

	#[test]
	fn write_extension_request_if_ekus_are_present() {
		let mut params = CertificateParams::default();
		params
			.extended_key_usages
			.push(ExtendedKeyUsagePurpose::ClientAuth);
		let key_pair = KeyPair::generate().unwrap();
		let csr = params.serialize_request(&key_pair).unwrap();
		let (_, parsed_csr) = X509CertificationRequest::from_der(csr.der()).unwrap();
		let requested_extensions = parsed_csr
			.requested_extensions()
			.unwrap()
			.collect::<Vec<_>>();
		assert!(matches!(
			requested_extensions.first().unwrap(),
			ParsedExtension::ExtendedKeyUsage(_)
		));
	}
}

#[cfg(feature = "x509-parser")]
mod test_csr {
	use rcgen::{
		CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, KeyPair,
		KeyUsagePurpose,
	};

	#[test]
	fn test_csr_roundtrip() {
		// We should be able to serialize a CSR, and then parse the CSR.
		let params = CertificateParams::default();
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![
			KeyUsagePurpose::DigitalSignature,
			KeyUsagePurpose::ContentCommitment,
			KeyUsagePurpose::KeyEncipherment,
			KeyUsagePurpose::DataEncipherment,
			KeyUsagePurpose::KeyAgreement,
			KeyUsagePurpose::KeyCertSign,
			KeyUsagePurpose::CrlSign,
			// It doesn't make sense to have both encipher and decipher only
			// So we'll take this opportunity to test omitting a key usage
			// KeyUsagePurpose::EncipherOnly,
			KeyUsagePurpose::DecipherOnly,
		];
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_extended_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.extended_key_usages = vec![
			ExtendedKeyUsagePurpose::ServerAuth,
			ExtendedKeyUsagePurpose::ClientAuth,
		];
		generate_and_test_parsed_csr(&params);
	}

	#[test]
	fn test_csr_with_key_usgaes_and_extended_key_usages_roundtrip() {
		let mut params = CertificateParams::default();
		params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
		params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
		generate_and_test_parsed_csr(&params);
	}

	fn generate_and_test_parsed_csr(params: &CertificateParams) {
		// Generate a key pair for the CSR
		let key_pair = KeyPair::generate().unwrap();
		// Serialize the CSR into DER from the given parameters
		let csr = params.serialize_request(&key_pair).unwrap();
		// Parse the CSR we just serialized
		let csrp = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

		// Ensure algorithms match.
		assert_eq!(key_pair.algorithm(), csrp.public_key.algorithm());
		// Assert that our parsed parameters match our initial parameters
		assert_eq!(*params, csrp.params);
	}
}
