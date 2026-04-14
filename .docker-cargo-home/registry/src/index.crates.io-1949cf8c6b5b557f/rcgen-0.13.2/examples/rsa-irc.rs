fn main() -> Result<(), Box<dyn std::error::Error>> {
	use rand::rngs::OsRng;
	use rsa::pkcs8::EncodePrivateKey;
	use rsa::RsaPrivateKey;

	use rcgen::{date_time_ymd, CertificateParams, DistinguishedName};
	use std::fmt::Write;
	use std::fs;

	let mut params: CertificateParams = Default::default();
	params.not_before = date_time_ymd(2021, 5, 19);
	params.not_after = date_time_ymd(4096, 1, 1);
	params.distinguished_name = DistinguishedName::new();

	let mut rng = OsRng;
	let bits = 2048;
	let private_key = RsaPrivateKey::new(&mut rng, bits)?;
	let private_key_der = private_key.to_pkcs8_der()?;
	let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();

	let cert = params.self_signed(&key_pair)?;
	let pem_serialized = cert.pem();
	let pem = pem::parse(&pem_serialized)?;
	let der_serialized = pem.contents();
	let hash = ring::digest::digest(&ring::digest::SHA512, der_serialized);
	let hash_hex = hash.as_ref().iter().fold(String::new(), |mut output, b| {
		let _ = write!(output, "{b:02x}");
		output
	});
	println!("sha-512 fingerprint: {hash_hex}");
	println!("{pem_serialized}");
	println!("{}", key_pair.serialize_pem());
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", pem_serialized.as_bytes())?;
	fs::write("certs/cert.der", der_serialized)?;
	fs::write("certs/key.pem", key_pair.serialize_pem().as_bytes())?;
	fs::write("certs/key.der", key_pair.serialize_der())?;
	Ok(())
}
