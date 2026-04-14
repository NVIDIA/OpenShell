# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.6](https://github.com/openssh-rust/openssh/compare/v0.11.5...v0.11.6) - 2025-12-03

### Fixed

- encoding of IPv6 addresses in `impl From<SocketAddr> for Socket` ([#179](https://github.com/openssh-rust/openssh/pull/179))

## [0.11.5](https://github.com/openssh-rust/openssh/compare/v0.11.4...v0.11.5) - 2025-01-09

### Added

- Log SSH commands (#175)

## [0.11.4](https://github.com/openssh-rust/openssh/compare/v0.11.3...v0.11.4) - 2024-11-27

### Fixed

- wait_with_output forget to close stdin ([#172](https://github.com/openssh-rust/openssh/pull/172))

### Other

- Bump codecov/codecov-action from 4 to 5 ([#169](https://github.com/openssh-rust/openssh/pull/169))

## [0.11.3](https://github.com/openssh-rust/openssh/compare/v0.11.2...v0.11.3) - 2024-11-06

### Other

- Update thiserror requirement from 1.0.30 to 2.0.0 ([#167](https://github.com/openssh-rust/openssh/pull/167))

## [0.11.2](https://github.com/openssh-rust/openssh/compare/v0.11.1...v0.11.2) - 2024-09-10

### Other

- Closing an existing port forward ([#165](https://github.com/openssh-rust/openssh/pull/165))

## [0.11.1](https://github.com/openssh-rust/openssh/compare/v0.11.0...v0.11.1) - 2024-09-08

### Other

- Add optional tracing support to Session drop impl ([#164](https://github.com/openssh-rust/openssh/pull/164))
- Update openssh-sftp-client requirement from 0.14.0 to 0.15.0 ([#159](https://github.com/openssh-rust/openssh/pull/159))

## [0.11.0](https://github.com/openssh-rust/openssh/compare/v0.10.5...v0.10.6) - 2024-08-10

- Remove dep tokio-pipe (#156)
- Remove deprecated functions (#156)
- Replace `From<tokio::proces::Child*>`
with `TryFrom<tokio::proces::Child*>`, since the converison is falliable (#156)
- Remove `IntoRawFd` for `Child*` since the conversion is falliable (#156)

## [0.10.5](https://github.com/openssh-rust/openssh/compare/v0.10.4...v0.10.5) - 2024-08-10

### Other
- Fix release-plz.yml
- Add missing feature doc for `Session::new*` ([#153](https://github.com/openssh-rust/openssh/pull/153))
- Create release-plz.yml for auto-release ([#151](https://github.com/openssh-rust/openssh/pull/151))
The changelog for this crate is kept in the project's Rust documentation in the changelog module.
