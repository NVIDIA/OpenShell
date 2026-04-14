
# Changes

## Release 0.13.1 - April 4th, 2024

Fixed:

- Fixed incorrect usage of the subject certificate's parameter's key identifier
  method when computing the key identifier of the issuer for the subject's
  authority key identifier (AKI) extension.

## Release 0.13.0 - March 28th, 2024

Breaking changes:

- The API used to create/issue key pairs, certificates, certificate signing
  requests (CSRs), and certificate revocation lists (CRLs) has been
  restructured to emphasize consistency and avoid common errors with
  serialization.

  For each concrete type (cert, CSR, CRL) the process is now the same:

  0. generate or load a key pair and any information about issuers required.
  1. create parameters, customizing as appropriate.
  2. call a generation `fn` on the parameters, providing subject key pair and
     issuer information and as appropriate.
  3. call serialization `fn`s on the finalized type, obtaining DER or PEM.

  For more information, see [rcgen/docs/0.12-to-0.13.md].

- Throughout the API DER inputs are now represented using types from the Rustls
  `rustls-pki-types` crate, e.g. `PrivateKeyDer`, `CertificateDer`,
  `CertificateSigningRequestDer`. Contributed by
  [Tudyx](https://github.com/tudyx).

- String types used in `SanType` and `DnValue` enums for non-UTF8 string types
  have been replaced with more specific types that prevent representation of
  illegal values. E.g. `Ia5String`, `BmpString`, `PrintableString`,
  `TeletexString`, and `UniversalString`. Contributed by
  [Tudyx](https://github.com/tudyx).

- Method names starting with `get_` have been renamed to match Rust convention:
  `CertificateRevocationList::get_params()` -> `params()`
  `Certificate::get_params()` -> `params()`
  `Certificate::get_key_identifier()` -> `Certificate::key_identifier()`
  `Certificate::get_times()` -> `Certificate::times()`

Added:

- RSA key generation support has been added. This support requires using the
  `aws-lc-rs` feature. By default using `KeyPair::generate_for()` with
  an RSA `SignatureAlgorithm` will generate an RSA 2048 keypair. See
  `KeyPair::generate_rsa_for()` for support for RSA 2048, 3072 and 4096 key sizes.

- Support for ECDSA P521 signatures and key generation has been added when using
  the `aws-lc-rs` feature. Contributed by [Alvenix](https://github.com/alvenix).

- Support for loading private keys that may be PKCS8, PKCS1, or SEC1 has been
  added when using the `aws-lc-rs` feature. Without this feature private keys
  must be PKCS8. See `KeyPair::from_pem_and_sign_algo()` and
  `KeyPair::from_der_and_sign_algo()` for more information. Contributed by
  [Alvenix](https://github.com/alvenix).

- Support has been added for Subject Alternative Name (SAN) names of type
  `OtherName`. Contributed by [Tudyx](https://github.com/tudyx).

- Support has been added for specifying custom "other" OIDs in extended key
  usage. Contributed by [Tudyx](https://github.com/tudyx).

- Support has been added for building rcgen _without_ cryptography by omitting
  the new (default-enabled) `crypto` feature flag. Contributed by
  [corrideat](https://github.com/corrideat).

- Support for using `aws-lc-rs` in `fips` mode can now be activated by using the
  `fips` feature in combination with the `aws-lc-rs` feature. Contributed by
  [BiagioFesta](https://github.com/biagiofesta).

- A small command-line tool for certificate generation (`rustls-cert-gen`) was
  added. Contributed by [tbro](https://github.com/tbro).

## Release 0.12.1 - January 25th, 2024

- RFC 5280 specifies that a serial number must not be larger than 20 octets in
  length. Prior to this release an unintended interaction between rcgen and its
  underlying DER encoding library could result in 21 octet serials. This has now
  been fixed.
- A regression that caused build errors when the optional `pem` feature was
  omitted has been fixed.

## Release 0.12.0 - December 16, 2023

- Rename `RcgenError` to `Error`. Contributed by [thomaseizinger](https://github.com/thomaseizinger).
- The public interface of `Error` has been made not expose external library types: `Error::PemError` now holds a `String` value, and the `Error` type doesn't support `From<_>` based conversion any more. This allows rcgen to update dependencies without impacting downstream users.
- Upgrade to `ring` `v0.17`. Contributed by [thomaseizinger](https://github.com/thomaseizinger).
- Make dependency on `ring` optional and allow usage of `aws-lc-rs` via a cargo feature. Ring remains the default. Contributed by [BiagioFesta](https://github.com/BiagioFesta).
- Add `Ia5String` support for `DistinguishedName`s.
- Add a `KeyIdMethod::PreSpecified` variant to set, and not generate the SKI. `CertificateParams::from_ca_cert_pem` now uses it when building params from an existing CA certificate. Contributed by [Brocar](https://github.com/Brocar).

## Release 0.11.3 - October 1, 2023

- Fix for import errors building without the optional `pem` feature.

## Release 0.11.2 - September 21, 2023

- `rcgen` has joined the umbrella of the [rustls](https://github.com/rustls) organization.
- Support for retrieving signature algorithm from `KeyPair`s. Contributed by [tindzk](https://github.com/tindzk).
- Fix for writing certificate signing requests (CSRs) with custom extensions from parameters without subject alternative names.
- Support for certificate CRL distribution points extension.
- Corrected OID for `ExtendedKeyUsagePurpose::Any`. Contributed by [jgallagher](https://github.com/jgallagher).
- Support for creating certificate revocation lists (CRLs).

## Release 0.11.1 - June 17, 2023

- Make botan a dev-dependency again. Contributed by [mbrubeck](https://github.com/mbrubeck).

## Release 0.11.0 - June 15, 2023

- Parse IP-address subject alternative names. Contributed by [iamjpotts](https://github.com/iamjpotts).
- Emit platform-apropriate line endings. Contributed by [frjonsen](https://github.com/frjonsen).
- Support larger serial numbers. Contributed by [andrenth](https://github.com/andrenth).
- Parse more certificate parameters. Contributed by [andrenth](https://github.com/andrenth).
- Output `SanType::IpAddress` when calling `CertificateParams::new` or `generate_simple_self_signed`. Contributed by [rukai](https://github.com/rukai).
- Update pem to 2.0. Contributed by [koushiro](https://github.com/koushiro).

## Release 0.10.0 - September 29, 2022

- Update x509-parser to 0.14.
- Increase minimum supported Rust version to 1.58.1.
- Update edition to 2021.
- Change `IsCa` enum to have `NoCa` and `ExplicitNoCa` and `Ca(...)`. Contributed by [doraneko94](https://github.com/doraneko94).

## Release 0.9.4 - September 28, 2022

* yanked due to breaking API changes, see 0.10.0 instead.

## Release 0.9.3 - July 16, 2022

- Add a `KeyPair::serialized_der` function. Contributed by [jean-airoldie](https://github.com/jean-airoldie).

## Release 0.9.2 - February 21, 2022

- Update x509-parser to 0.13. Contributed by [matze](https://github.com/matze).

## Release 0.9.1 - February 9, 2022

- Change edition to 2018 in order to support Rust 1.53.0.

## Release 0.9.0 - February 2, 2022

- Add RemoteKeyError for usage by remote keys.
- Support non utf8 strings. Contributed by [omjadas](https://github.com/omjadas).
- Switch from chrono to time. Contributed by [connec](https://github.com/connec).
- Update edition to 2021.

## Release 0.8.14 - October 14, 2021

- Update pem to 1.0.
- Update x509-parser to 0.12.

## Release 0.8.13 - August 22, 2021

- Bugfix release to make Certificate `Send` and `Sync` again.

## Release 0.8.12 - August 22, 2021

- Use public key as default serial number. Contributed by [jpastuszek](https://github.com/jpastuszek).
- Add support for `PKCS_RSA_SHA512` and `PKCS_RSA_SHA384` signature algorithms.
- Add support for the keyUsage extension. Contributed by [jaredwolff](https://github.com/jaredwolff).
- Ability to use remote keys. Contributed by [daxpedda](https://github.com/daxpedda).

## Release 0.8.11 - April 28, 2021

- Add getters for the criticality, content, and `oid_components` of a `CustomExtension`
- Update yasna to 0.4

## Release 0.8.10 - April 15, 2021

- Implement some additional traits for some of the types. Contributed by [zurborg](https://github.com/zurborg).
- Adoption of intra-doc-links
- Addition of the ability to zero key pairs. Contributed by [didier-wenzek](https://github.com/didier-wenzek).

## Release 0.8.9 - December 4, 2020

- Switch CI to Github Actions.
- Strip nanos from `DateTime` as well. Contributed by [@trevor-crypto](https://github.com/trevor-crypto).

## Release 0.8.7 - December 1, 2020

- Turn `botan` back into a dev-dependency. Contributed by [@nthuemmel](https://github.com/nthuemmel).
- Fix signing when CA uses different signing algorithm . Contributed by [@nthuemmel](https://github.com/nthuemmel).

## Release 0.8.6 - December 1, 2020

- Add `KeyPair::from_der`
- Add botan based test to the testsuite
- Update x509-parser to 0.9. Contributed by [@djc](https://github.com/djc).
- Ability to create certificates from CSRs. Contributed by [@djc](https://github.com/djc).

## Release 0.8.5 - June 29, 2020

- Add some more `DnType`s: `OrganizationalUnitName`, `LocalityName`, `StateOrProvinceName`
- Add `remove` function to `DistinguishedName`
- Add ability to specify `NameConstraints`

## Release 0.8.4 - June 5, 2020

- Improve spec compliance in the `notBefore`/`notAfter` fields generated by using `UTCTime` if needed

## Release 0.8.3 - May 24, 2020

- Fix regression of `0.8.1` that generated standards non compliant CSRs
  and broke Go toolchain parsers. Contributed by [@thomastaylor312](https://github.com/thomastaylor312).

## Release 0.8.2 - May 18, 2020

- Disable `chrono` default features to get rid of time crate
- Improve `openssl` tests to do a full handshake with the generated cert

## Release 0.8.1 - April 2, 2020

- Fix non-standard-compliant SubjectKeyIdentifier X.509v3 extension format
- BasicConstraints X.509v3 extension is now marked as critical
- Use RFC 7093 to calculate calculate subject key identifiers
- Add option to insert AuthorityKeyIdentifier X.509v3 extension into non-self-signed certificates
- Update to x509-parser 0.7

## Release 0.8.0 - March 12, 2020

- Update to pem 0.7
- Correct number of nanoseconds per second. Contributed by [@samlich](https://github.com/samlich).
- Adoption of the `non_exhaustive` feature in the API

## Release 0.7.0 - September 14, 2019

- Bugfix release for ip address subject alternative names.
  Turns out they aren't CIDR subnets after all :)

## Release 0.6.0 - September 12, 2019

- Support for email and cidr subnet (ip address) subject alternative names
- Support for the extended key usage extension

## Release 0.5.1 - August 19, 2019

- Update to x509-parser 0.6

## Release 0.5.0 - July 19, 2019

- Update to ring 0.16 and webpki 0.21
- Update to x509-parser 0.5
- Expose an API to get the raw public key of a key pair

## Release 0.4.1 - June 28, 2019

- Allow inspection of `DistinguishedName` via iterators and get functions
- Fix a bug in `is_compatible` not saying false. Contributed by [@fzgregor](https://github.com/fzgregor).
- Extend the public interface of `KeyPair`. Contributed by [@fzgregor](https://github.com/fzgregor).

## Release 0.4.0 - June 18, 2019

- Support for user supplied keypairs. Contributed by [@fzgregor](https://github.com/fzgregor).
- Support for signing with user supplied CA certificates. Contributed by [@fzgregor](https://github.com/fzgregor).
- Correct a bug with distinguished name serialization ([PR link](https://github.com/est31/rcgen/pull/13)). Contributed by [@fzgregor](https://github.com/fzgregor).
- Addition of limited (no key generation) RSA support
- Proper error handling with `Result` and our own Error type
- Improvements of the testsuite

## Release 0.3.1 - June 6, 2019

- Ability to disable the dependency on the `pem` crate
- Support for creating CSRs (Certificate Signing Requests). Contributed by [@djc](https://github.com/djc).
- Ability to specify custom extensions for certificates
- Ability to craft `acmeIdentifier` extensions
- Update yasna to 0.3.0

## Release 0.3.0 - May 18, 2019

- Support for CA certificate generation. Contributed by [@djc](https://github.com/djc).
- Support for certificate signing. Contributed by [@djc](https://github.com/djc).
- Support for ED25519 certificates
- Support for SHA-384 certificates
- API cleanups (Future proofing CertificateParams, public constant renames)

## Release 0.2.1 - April 26, 2019

- Updated to pem 0.6

## Release 0.2 - January 10, 2019

- Updated to ring 0.14.0

## Release 0.1 - January 7, 2019

Initial release. Ability to generate self-signed ECDSA keys.
