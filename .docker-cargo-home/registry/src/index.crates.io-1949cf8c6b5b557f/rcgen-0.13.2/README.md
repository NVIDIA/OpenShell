# rcgen

[![docs](https://docs.rs/rcgen/badge.svg)](https://docs.rs/rcgen)
[![crates.io](https://img.shields.io/crates/v/rcgen.svg)](https://crates.io/crates/rcgen)
[![dependency status](https://deps.rs/repo/github/est31/rcgen/status.svg)](https://deps.rs/repo/github/est31/rcgen)

Simple Rust library to generate X.509 certificates.

```Rust
use rcgen::{generate_simple_self_signed, CertifiedKey};
// Generate a certificate that's valid for "localhost" and "hello.world.example"
let subject_alt_names = vec!["hello.world.example".to_string(),
	"localhost".to_string()];

let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();
println!("{}", cert.pem());
println!("{}", key_pair.serialize_pem());
```

## Trying it out with openssl

You can do this:

```
cargo run
openssl x509 -in certs/cert.pem -text -noout
```

For debugging, pasting the PEM formatted text
to [this](https://lapo.it/asn1js/) service is very useful.

## Trying it out with quinn

You can use rcgen together with the [quinn](https://github.com/quinn-rs/quinn) crate.
The whole set of commands is:
```
cargo run
cd ../quinn
cargo run --example server -- --cert ../rcgen/certs/cert.pem --key ../rcgen/certs/key.pem ./
cargo run --example client -- --ca ../rcgen/certs/cert.der https://localhost:4433/README.md

```

## MSRV

The MSRV policy is to strive for supporting 7-month old Rust versions.

### License
[license]: #license

This crate is distributed under the terms of both the MIT license
and the Apache License (Version 2.0), at your option.

See [LICENSE](LICENSE) for details.

#### License of your contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
