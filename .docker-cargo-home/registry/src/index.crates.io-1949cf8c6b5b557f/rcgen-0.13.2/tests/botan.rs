#![cfg(all(feature = "crypto", feature = "x509-parser"))]

use time::{Duration, OffsetDateTime};

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa};
use rcgen::{CertificateRevocationListParams, RevocationReason, RevokedCertParams};
use rcgen::{DnValue, KeyPair};
use rcgen::{KeyUsagePurpose, SerialNumber};

mod util;

fn default_params() -> (CertificateParams, KeyPair) {
	let (mut params, key_pair) = util::default_params();
	// Botan has a sanity check that enforces a maximum expiration date
	params.not_after = rcgen::date_time_ymd(3016, 1, 1);
	(params, key_pair)
}

fn check_cert(cert_der: &[u8], cert: &Certificate) {
	println!("{}", cert.pem());
	check_cert_ca(cert_der, cert, cert_der);
}

fn check_cert_ca(cert_der: &[u8], _cert: &Certificate, ca_der: &[u8]) {
	println!(
		"botan version: {}",
		botan::Version::current().unwrap().string
	);
	let trust_anchor = botan::Certificate::load(ca_der).unwrap();
	let end_entity_cert = botan::Certificate::load(cert_der).unwrap();

	// Set time to Jan 10, 2004
	const REFERENCE_TIME: Option<u64> = Some(0x40_00_00_00);

	// Verify the certificate
	end_entity_cert
		.verify(
			&[],
			&[&trust_anchor],
			None,
			Some("crabs.crabs"),
			REFERENCE_TIME,
		)
		.unwrap();

	// TODO perform a full handshake
}

#[test]
fn test_botan() {
	let (params, key_pair) = default_params();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_256() {
	let (params, _) = default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_384() {
	let (params, _) = default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
#[cfg(feature = "aws_lc_rs")]
fn test_botan_521() {
	let (params, _) = default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_25519() {
	let (params, _) = default_params();
	let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_25519_v1_given() {
	let (params, _) = default_params();
	let key_pair = KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V1).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_25519_v2_given() {
	let (params, _) = default_params();
	let key_pair = KeyPair::from_pem(util::ED25519_TEST_KEY_PAIR_PEM_V2).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_rsa_given() {
	let (params, _) = default_params();
	let key_pair = KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
	let cert = params.self_signed(&key_pair).unwrap();

	// Now verify the certificate.
	check_cert(cert.der(), &cert);
}

#[test]
fn test_botan_separate_ca() {
	let (mut params, ca_key) = default_params();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = params.self_signed(&ca_key).unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");
	// Botan has a sanity check that enforces a maximum expiration date
	params.not_after = rcgen::date_time_ymd(3016, 1, 1);

	let key_pair = KeyPair::generate().unwrap();
	let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
	check_cert_ca(cert.der(), &cert, ca_cert.der());
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_botan_imported_ca() {
	let (mut params, ca_key) = default_params();
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
	// Botan has a sanity check that enforces a maximum expiration date
	params.not_after = rcgen::date_time_ymd(3016, 1, 1);

	let key_pair = KeyPair::generate().unwrap();
	let cert = params
		.signed_by(&key_pair, &imported_ca_cert, &ca_key)
		.unwrap();
	check_cert_ca(cert.der(), &cert, ca_cert_der);
}

#[cfg(feature = "x509-parser")]
#[test]
fn test_botan_imported_ca_with_printable_string() {
	let (mut params, imported_ca_key) = default_params();
	params.distinguished_name.push(
		DnType::CountryName,
		DnValue::PrintableString("US".try_into().unwrap()),
	);
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let ca_cert = params.self_signed(&imported_ca_key).unwrap();

	let ca_cert_der = ca_cert.der();

	let imported_ca_cert_params = CertificateParams::from_ca_cert_der(ca_cert_der).unwrap();
	let imported_ca_cert = imported_ca_cert_params
		.self_signed(&imported_ca_key)
		.unwrap();

	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::OrganizationName, "Crab widgits SE");
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");
	// Botan has a sanity check that enforces a maximum expiration date
	params.not_after = rcgen::date_time_ymd(3016, 1, 1);
	let key_pair = KeyPair::generate().unwrap();
	let cert = params
		.signed_by(&key_pair, &imported_ca_cert, &imported_ca_key)
		.unwrap();

	check_cert_ca(cert.der(), &cert, ca_cert_der);
}

#[test]
fn test_botan_crl_parse() {
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
	ee.serial_number = Some(SerialNumber::from(99999));
	// Botan has a sanity check that enforces a maximum expiration date
	ee.not_after = rcgen::date_time_ymd(3016, 1, 1);
	let ee_key = KeyPair::generate_for(alg).unwrap();
	let ee = ee.signed_by(&ee_key, &issuer, &issuer_key).unwrap();
	let botan_ee = botan::Certificate::load(ee.der()).unwrap();

	// Generate a CRL with the issuer that revokes the EE cert.
	let now = OffsetDateTime::now_utc();
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
	};

	let crl = crl.signed_by(&issuer, &issuer_key).unwrap();

	// We should be able to load the CRL in both serializations.
	botan::CRL::load(crl.pem().unwrap().as_ref()).unwrap();
	let crl = botan::CRL::load(crl.der()).unwrap();

	// We should find the EE cert revoked.
	assert!(crl.is_revoked(&botan_ee).unwrap());
}
