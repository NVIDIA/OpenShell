#![cfg(feature = "crypto")]

use std::time::Duration as StdDuration;

use pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair as _};
#[cfg(feature = "pem")]
use ring::signature::{RsaEncoding, RsaKeyPair};
use time::{Duration, OffsetDateTime};
use webpki::{
	anchor_from_trusted_cert, BorrowedCertRevocationList, CertRevocationList, EndEntityCert,
	KeyUsage, RevocationOptionsBuilder,
};

use rcgen::{
	BasicConstraints, Certificate, CertificateParams, DnType, Error, IsCa, KeyPair, RemoteKeyPair,
};
use rcgen::{CertificateRevocationListParams, RevocationReason, RevokedCertParams};
#[cfg(feature = "x509-parser")]
use rcgen::{CertificateSigningRequestParams, DnValue};
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose, SerialNumber};

mod util;

fn sign_msg_ecdsa(key_pair: &KeyPair, msg: &[u8], alg: &'static EcdsaSigningAlgorithm) -> Vec<u8> {
	let pk_der = key_pair.serialize_der();
	let key_pair =
		EcdsaKeyPair::from_pkcs8(alg, &pk_der, &ring::rand::SystemRandom::new()).unwrap();
	let system_random = SystemRandom::new();
	let signature = key_pair.sign(&system_random, msg).unwrap();
	signature.as_ref().to_vec()
}

fn sign_msg_ed25519(key_pair: &KeyPair, msg: &[u8]) -> Vec<u8> {
	let pk_der = key_pair.serialize_der();
	let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pk_der).unwrap();
	let signature = key_pair.sign(msg);
	signature.as_ref().to_vec()
}

#[cfg(feature = "pem")]
fn sign_msg_rsa(key_pair: &KeyPair, msg: &[u8], encoding: &'static dyn RsaEncoding) -> Vec<u8> {
	let pk_der = key_pair.serialize_der();
	let key_pair = RsaKeyPair::from_pkcs8(&pk_der).unwrap();
	let system_random = SystemRandom::new();
	let mut signature = vec![0; key_pair.public().modulus_len()];
	key_pair
		.sign(encoding, &system_random, msg, &mut signature)
		.unwrap();
	signature
}

fn check_cert<'a, 'b>(
	cert_der: &CertificateDer<'_>,
	cert: &'a Certificate,
	cert_key: &'a KeyPair,
	alg: &dyn SignatureVerificationAlgorithm,
	sign_fn: impl FnOnce(&'a KeyPair, &'b [u8]) -> Vec<u8>,
) {
	#[cfg(feature = "pem")]
	{
		println!("{}", cert.pem());
	}
	check_cert_ca(cert_der, cert_key, cert_der, alg, alg, sign_fn);
}

fn check_cert_ca<'a, 'b>(
	cert_der: &CertificateDer<'_>,
	cert_key: &'a KeyPair,
	ca_der: &CertificateDer<'_>,
	cert_alg: &dyn SignatureVerificationAlgorithm,
	ca_alg: &dyn SignatureVerificationAlgorithm,
	sign_fn: impl FnOnce(&'a KeyPair, &'b [u8]) -> Vec<u8>,
) {
	let trust_anchor = anchor_from_trusted_cert(ca_der).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let end_entity_cert = EndEntityCert::try_from(cert_der).unwrap();

	// Set time to Jan 10, 2004
	let time = UnixTime::since_unix_epoch(StdDuration::from_secs(0x40_00_00_00));

	// (1/3) Check whether the cert is valid
	end_entity_cert
		.verify_for_usage(
			&[cert_alg, ca_alg],
			&trust_anchor_list[..],
			&[],
			time,
			KeyUsage::server_auth(),
			None,
			None,
		)
		.expect("valid TLS server cert");

	// (2/3) Check that the cert is valid for the given DNS name
	let dns_name = ServerName::try_from("crabs.crabs").unwrap();
	end_entity_cert
		.verify_is_valid_for_subject_name(&dns_name)
		.expect("valid for DNS name");

	// (3/3) Check that a message signed by the cert is valid.
	let msg = b"Hello, World! This message is signed.";
	let signature = sign_fn(cert_key, msg);
	end_entity_cert
		.verify_signature(cert_alg, msg, &signature)
		.expect("signature is valid");
}

#[test]
fn test_webpki() {
	let (params, key_pair) = util::default_params();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	let sign_fn =
		|key_pair, msg| sign_msg_ecdsa(key_pair, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[test]
fn test_webpki_256() {
	let (params, _) = util::default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[test]
fn test_webpki_384() {
	let (params, _) = util::default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P384_SHA384_ASN1_SIGNING);
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ECDSA_P384_SHA384,
		sign_fn,
	);
}

#[test]
fn test_webpki_25519() {
	let (params, _) = util::default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ED25519,
		sign_msg_ed25519,
	);
}

#[cfg(feature = "pem")]
#[test]
fn test_webpki_25519_v1_given() {
	let (params, _) = util::default_params();
	let key_pair = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V1).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ED25519,
		sign_msg_ed25519,
	);
}

#[cfg(feature = "pem")]
#[test]
fn test_webpki_25519_v2_given() {
	let (params, _) = util::default_params();
	let key_pair = rcgen::KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V2).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ED25519,
		sign_msg_ed25519,
	);
}

#[cfg(feature = "pem")]
#[test]
fn test_webpki_rsa_given() {
	let (params, _) = util::default_params();
	let key_pair = rcgen::KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::RSA_PKCS1_2048_8192_SHA256,
		|msg, cert| sign_msg_rsa(msg, cert, &signature::RSA_PKCS1_SHA256),
	);
}

#[cfg(feature = "pem")]
#[test]
fn test_webpki_rsa_combinations_given() {
	let configs: &[(_, _, &'static dyn signature::RsaEncoding)] = &[
		(
			&rcgen::PKCS_RSA_SHA256,
			webpki::ring::RSA_PKCS1_2048_8192_SHA256,
			&signature::RSA_PKCS1_SHA256,
		),
		(
			&rcgen::PKCS_RSA_SHA384,
			webpki::ring::RSA_PKCS1_2048_8192_SHA384,
			&signature::RSA_PKCS1_SHA384,
		),
		(
			&rcgen::PKCS_RSA_SHA512,
			webpki::ring::RSA_PKCS1_2048_8192_SHA512,
			&signature::RSA_PKCS1_SHA512,
		),
		//(&rcgen::PKCS_RSA_PSS_SHA256, &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, &signature::RSA_PSS_SHA256),
	];
	for c in configs {
		let (params, _) = util::default_params();
		let key_pair =
			rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(util::RSA_TEST_KEY_PAIR_PEM, c.0).unwrap();
		let cert = params.self_signed(&key_pair).unwrap();

		// Now verify the certificate.
		check_cert(cert.der(), &cert, &key_pair, c.1, |msg, cert| {
			sign_msg_rsa(msg, cert, c.2)
		});
	}
}

#[test]
fn test_webpki_separate_ca() {
	let (mut params, ca_key) = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = params.self_signed(&ca_key).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");

	let key_pair = KeyPair::generate().unwrap();
	let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(
		cert.der(),
		&key_pair,
		ca_cert.der(),
		webpki::ring::ECDSA_P256_SHA256,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[test]
fn test_webpki_separate_ca_with_other_signing_alg() {
	let (mut params, _) = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
	let ca_cert = params.self_signed(&ca_key).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");

	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
	check_cert_ca(
		cert.der(),
		&key_pair,
		ca_cert.der(),
		webpki::ring::ED25519,
		webpki::ring::ECDSA_P256_SHA256,
		sign_msg_ed25519,
	);
}

#[test]
fn from_remote() {
	struct Remote(EcdsaKeyPair);

	impl RemoteKeyPair for Remote {
		fn public_key(&self) -> &[u8] {
			self.0.public_key().as_ref()
		}

		fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
			let system_random = SystemRandom::new();
			self.0
				.sign(&system_random, msg)
				.map(|s| s.as_ref().to_owned())
				.map_err(|_| Error::RingUnspecified)
		}

		fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
			&rcgen::PKCS_ECDSA_P256_SHA256
		}
	}

	let rng = ring::rand::SystemRandom::new();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
	let remote = EcdsaKeyPair::from_pkcs8(
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
		&key_pair.serialize_der(),
		&rng,
	)
	.unwrap();
	let key_pair = EcdsaKeyPair::from_pkcs8(
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
		&key_pair.serialize_der(),
		&rng,
	)
	.unwrap();
	let remote = KeyPair::from_remote(Box::new(Remote(remote))).unwrap();

	let (params, _) = util::default_params();
	let cert = params.self_signed(&remote).unwrap();

	// Now verify the certificate.
	let sign_fn = move |_, msg| {
		let system_random = SystemRandom::new();
		let signature = key_pair.sign(&system_random, msg).unwrap();
		signature.as_ref().to_vec()
	};
	check_cert(
		cert.der(),
		&cert,
		&remote,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

/*
// TODO https://github.com/briansmith/webpki/issues/134
// TODO https://github.com/briansmith/webpki/issues/135
#[test]
fn test_webpki_separate_ca_name_constraints() {
	let mut params = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.name_constraints = Some(NameConstraints {
		// TODO also add a test with non-empty permitted_subtrees that
		// doesn't contain a DirectoryName entry. This isn't possible
		// currently due to a limitation of webpki.
		permitted_subtrees : vec![GeneralSubtree::DnsName("dev".to_string()), GeneralSubtree::DirectoryName(rcgen::DistinguishedName::new())],
		//permitted_subtrees : vec![GeneralSubtree::DnsName("dev".to_string())],
		//permitted_subtrees : Vec::new(),
		//excluded_subtrees : vec![GeneralSubtree::DnsName("v".to_string())],
		excluded_subtrees : Vec::new(),
	});

	let ca_cert = Certificate::from_params(params).unwrap();
	println!("{}", ca_cert.serialize_pem().unwrap());

	let ca_der = ca_cert.serialize_der().unwrap();

	let mut params = CertificateParams::new(vec!["crabs.dev".to_string()]);
	params.distinguished_name = rcgen::DistinguishedName::new();
	//params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	//params.distinguished_name.push(DnType::CommonName, "Dev domain");
	let cert = Certificate::from_params(params).unwrap();
	let cert_der = cert.serialize_der_with_signer(&ca_cert).unwrap();
	println!("{}", cert.serialize_pem_with_signer(&ca_cert).unwrap());

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg,
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(&cert_der, &cert, &ca_der,
		&webpki::ECDSA_P256_SHA256, &webpki::ECDSA_P256_SHA256, sign_fn);
}
*/

#[cfg(feature = "x509-parser")]
#[test]
fn test_webpki_imported_ca() {
	let (mut params, ca_key) = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.key_usages.push(KeyUsagePurpose::KeyCertSign);
	let ca_cert = params.self_signed(&ca_key).unwrap();

	let ca_cert_der = ca_cert.der();

	let imported_ca_cert_params = CertificateParams::from_ca_cert_der(ca_cert_der).unwrap();
	assert_eq!(
		imported_ca_cert_params.key_usages,
		vec![KeyUsagePurpose::KeyCertSign]
	);
	let imported_ca_cert = imported_ca_cert_params.self_signed(&ca_key).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");
	let cert_key = KeyPair::generate().unwrap();
	let cert = params
		.signed_by(&cert_key, &imported_ca_cert, &ca_key)
		.unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(
		cert.der(),
		&cert_key,
		ca_cert_der,
		webpki::ring::ECDSA_P256_SHA256,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_webpki_imported_ca_with_printable_string() {
	let (mut params, ca_key) = util::default_params();
	params.distinguished_name.push(
		DnType::CountryName,
		DnValue::PrintableString("US".try_into().unwrap()),
	);
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = params.self_signed(&ca_key).unwrap();

	let ca_cert_der = ca_cert.der();

	let imported_ca_cert_params = CertificateParams::from_ca_cert_der(ca_cert_der).unwrap();
	let imported_ca_cert = imported_ca_cert_params.self_signed(&ca_key).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");
	let cert_key = KeyPair::generate().unwrap();
	let cert = params
		.signed_by(&cert_key, &imported_ca_cert, &ca_key)
		.unwrap();

	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(
		cert.der(),
		&cert_key,
		ca_cert_der,
		webpki::ring::ECDSA_P256_SHA256,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_certificate_from_csr() {
	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");

	let eku_test = vec![
		ExtendedKeyUsagePurpose::Any,
		ExtendedKeyUsagePurpose::ClientAuth,
		ExtendedKeyUsagePurpose::CodeSigning,
		ExtendedKeyUsagePurpose::EmailProtection,
		ExtendedKeyUsagePurpose::OcspSigning,
		ExtendedKeyUsagePurpose::ServerAuth,
		ExtendedKeyUsagePurpose::TimeStamping,
	];
	for eku in &eku_test {
		params.insert_extended_key_usage(eku.clone());
	}

	let cert_key = KeyPair::generate().unwrap();
	let csr = params.serialize_request(&cert_key).unwrap();
	let csr = CertificateSigningRequestParams::from_der(csr.der()).unwrap();

	let ekus_contained = &csr.params.extended_key_usages;
	for eku in &eku_test {
		assert!(ekus_contained.contains(eku));
	}

	let (mut params, ca_key) = util::default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	for eku in &eku_test {
		params.insert_extended_key_usage(eku.clone());
	}
	let ekus_contained = &params.extended_key_usages;
	for eku in &eku_test {
		assert!(ekus_contained.contains(eku));
	}

	let ca_cert = params.self_signed(&ca_key).unwrap();

	let ekus_contained = &ca_cert.params().extended_key_usages;
	for eku in &eku_test {
		assert!(ekus_contained.contains(eku));
	}

	let cert = csr.signed_by(&ca_cert, &ca_key).unwrap();

	let ekus_contained = &cert.params().extended_key_usages;
	for eku in &eku_test {
		assert!(ekus_contained.contains(eku));
	}

	let eku_cert = &ca_cert.params().extended_key_usages;
	for eku in &eku_test {
		assert!(eku_cert.contains(eku));
	}

	let sign_fn =
		|key_pair, msg| sign_msg_ecdsa(key_pair, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert_ca(
		cert.der(),
		&cert_key,
		ca_cert.der(),
		webpki::ring::ECDSA_P256_SHA256,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[test]
fn test_webpki_serial_number() {
	let (mut params, key_pair) = util::default_params();
	params.serial_number = Some(vec![0, 1, 2].into());
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	let sign_fn = |cert, msg| sign_msg_ecdsa(cert, msg, &signature::ECDSA_P256_SHA256_ASN1_SIGNING);
	check_cert(
		cert.der(),
		&cert,
		&key_pair,
		webpki::ring::ECDSA_P256_SHA256,
		sign_fn,
	);
}

#[test]
fn test_webpki_crl_parse() {
	// Create a CRL with one revoked cert, and an issuer to sign the CRL.
	let (crl, _) = util::test_crl();
	let revoked_cert = crl.params().revoked_certs.first().unwrap();

	// We should be able to parse the CRL DER without error.
	let webpki_crl = CertRevocationList::from(
		BorrowedCertRevocationList::from_der(crl.der()).expect("failed to parse CRL DER"),
	);

	// We should be able to find the revoked cert with the expected properties.
	let webpki_revoked_cert = webpki_crl
		.find_serial(revoked_cert.serial_number.as_ref())
		.expect("failed to parse revoked certs in CRL")
		.expect("failed to find expected revoked cert in CRL");
	assert_eq!(
		webpki_revoked_cert.serial_number,
		revoked_cert.serial_number.as_ref()
	);
	assert_eq!(
		webpki_revoked_cert.reason_code.unwrap() as u64,
		revoked_cert.reason_code.unwrap() as u64
	);
	assert_eq!(
		webpki_revoked_cert.revocation_date,
		UnixTime::since_unix_epoch(StdDuration::from_secs(
			revoked_cert.revocation_time.unix_timestamp() as u64
		))
	);
}

#[test]
fn test_webpki_crl_revoke() {
	// Create an issuer CA.
	let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
	let (mut issuer, _) = util::default_params();
	issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	issuer.key_usages = vec![
		KeyUsagePurpose::KeyCertSign,
		KeyUsagePurpose::DigitalSignature,
		KeyUsagePurpose::CrlSign,
	];
	let issuer_key = KeyPair::generate_for(alg).unwrap();
	let issuer = issuer.self_signed(&issuer_key).unwrap();

	// Create an end entity cert issued by the issuer.
	let (mut ee, _) = util::default_params();
	ee.is_ca = IsCa::NoCa;
	ee.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
	ee.serial_number = Some(SerialNumber::from(99999));
	let ee_key = KeyPair::generate_for(alg).unwrap();
	let ee = ee.signed_by(&ee_key, &issuer, &issuer_key).unwrap();

	// Set up webpki's verification requirements.
	let trust_anchor = anchor_from_trusted_cert(issuer.der()).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let end_entity_cert = EndEntityCert::try_from(ee.der()).unwrap();
	let unix_time = 0x40_00_00_00;
	let time = UnixTime::since_unix_epoch(StdDuration::from_secs(unix_time));

	// The end entity cert should validate with the issuer without error.
	end_entity_cert
		.verify_for_usage(
			&[webpki::ring::ECDSA_P256_SHA256],
			&trust_anchor_list[..],
			&[],
			time,
			KeyUsage::client_auth(),
			None,
			None,
		)
		.expect("failed to validate ee cert with issuer");

	// Generate a CRL with the issuer that revokes the EE cert.
	let now = OffsetDateTime::from_unix_timestamp(unix_time as i64).unwrap();
	let crl = CertificateRevocationListParams {
		this_update: now,
		next_update: now + Duration::weeks(1),
		crl_number: rcgen::SerialNumber::from(1234),
		issuing_distribution_point: None,
		revoked_certs: vec![RevokedCertParams {
			serial_number: ee.params().serial_number.clone().unwrap(),
			revocation_time: now,
			reason_code: Some(RevocationReason::KeyCompromise),
			invalidity_date: None,
		}],
		key_identifier_method: rcgen::KeyIdMethod::Sha256,
	}
	.signed_by(&issuer, &issuer_key)
	.unwrap();

	let crl = CertRevocationList::from(BorrowedCertRevocationList::from_der(crl.der()).unwrap());

	// The end entity cert should **not** validate when we provide a CRL that revokes the EE cert.
	let result = end_entity_cert.verify_for_usage(
		&[webpki::ring::ECDSA_P256_SHA256],
		&trust_anchor_list[..],
		&[],
		time,
		KeyUsage::client_auth(),
		Some(RevocationOptionsBuilder::new(&[&crl]).unwrap().build()),
		None,
	);
	assert!(matches!(result, Err(webpki::Error::CertRevoked)));
}

#[test]
fn test_webpki_cert_crl_dps() {
	let der = util::cert_with_crl_dps();
	let cert = CertificateDer::from(der);
	webpki::EndEntityCert::try_from(&cert).expect("failed to parse cert with CRL DPs ext");
	// Webpki doesn't expose the parsed CRL distribution extension, so we can't interrogate that
	// it matches the expected form. See `openssl.rs` for more extensive coverage.
}
