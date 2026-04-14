# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.9](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.8...z3-sys-v0.10.9) - 2026-03-13

### Other

- Update zip dependency to latest ([#515](https://github.com/prove-rs/z3.rs/pull/515)) (by @ThomasTNO) - #515

### Contributors

* @ThomasTNO

## [0.10.8](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.7...z3-sys-v0.10.8) - 2026-03-06

### Fixed

- *(z3-sys)* raise GitHub download timeout for gh-release ([#513](https://github.com/prove-rs/z3.rs/pull/513)) (by @milevin)

### Contributors

* @milevin

## [0.10.7](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.6...z3-sys-v0.10.7) - 2026-02-24

### Added

- algebraic numbers, polynomials, enhanced floats, AST vectors, and quantifier elimination ([#500](https://github.com/prove-rs/z3.rs/pull/500)) (by @toolCHAINZ, @NikolajBjorner) - #500

### Other

- bump Z3 default version to 4.16.0 ([#504](https://github.com/prove-rs/z3.rs/pull/504)) (by @toolCHAINZ) - #504

### Contributors

* @toolCHAINZ
* @NikolajBjorner

## [0.10.6](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.5...z3-sys-v0.10.6) - 2026-02-21

### Fixed

- add rerun-if-env-changed for Z3_SYS_BUNDLED_DIR_OVERRIDE ([#496](https://github.com/prove-rs/z3.rs/pull/496)) (by @toolCHAINZ) - #496

### Other

- expand build flag documentation ([#499](https://github.com/prove-rs/z3.rs/pull/499)) (by @toolCHAINZ) - #499

### Contributors

* @toolCHAINZ

## [0.10.5](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.4...z3-sys-v0.10.5) - 2026-02-13

### Fixed

- Z3_SYS_BUNDLED_DIR_OVERRIDE had extra z3 ([#491](https://github.com/prove-rs/z3.rs/pull/491)) (by @toolCHAINZ) - #491

### Contributors

* @toolCHAINZ

## [0.10.4](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.3...z3-sys-v0.10.4) - 2025-12-27

### Added

- allow configuring tls provider for `gh-release` and `bundled` ([#486](https://github.com/prove-rs/z3.rs/pull/486)) (by @toolCHAINZ) - #486

### Contributors

* @toolCHAINZ

## [0.10.3](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.2...z3-sys-v0.10.3) - 2025-11-20

### Added

- Use native-tls-vendored feature of reqwest dependency ([#472](https://github.com/prove-rs/z3.rs/pull/472)) (by @grebnetiew) - #472

### Contributors

* @grebnetiew

## [0.10.2](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.1...z3-sys-v0.10.2) - 2025-11-17

### Fixed

- do not scrape GitHub when submodule exists ([#468](https://github.com/prove-rs/z3.rs/pull/468)) (by @toolCHAINZ) - #468

### Other

- bump bundled z3 ([#470](https://github.com/prove-rs/z3.rs/pull/470)) (by @toolCHAINZ) - #470

### Contributors

* @toolCHAINZ

## [0.10.1](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.10.0...z3-sys-v0.10.1) - 2025-11-16

### Added

- Implement support for bundling z3 without use of github checkout ([#464](https://github.com/prove-rs/z3.rs/pull/464)) (by @ThomasTNO) - #464

### Contributors

* @ThomasTNO

## [0.10.0](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.10...z3-sys-v0.10.0) - 2025-09-26

### Added

- Special Binary Relation FuncDecls ([#340](https://github.com/prove-rs/z3.rs/pull/340)) (by @grahnen) - #340

### Changed

- [**breaking**] Fallible z3-sys APIs now return Option<NonNull<T>> ([#450](https://github.com/prove-rs/z3.rs/pull/450)) (by @toolCHAINZ) - #450

### Contributors

* @toolCHAINZ
* @grahnen

## [0.9.10](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.9...z3-sys-v0.9.10) - 2025-09-08

### Other

- Add nostd tags ([#435](https://github.com/prove-rs/z3.rs/pull/435)) (by @toolCHAINZ) - #435

### Contributors

* @toolCHAINZ

## [0.9.9](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.8...z3-sys-v0.9.9) - 2025-09-03

### Added

- *(z3-sys)* do not depend on std ([#425](https://github.com/prove-rs/z3.rs/pull/425)) (by @lucascool12)

### Contributors

* @lucascool12

## [0.9.8](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.7...z3-sys-v0.9.8) - 2025-08-25

### Fixed

- use proper header path on overridden build ([#423](https://github.com/prove-rs/z3.rs/pull/423)) (by @toolCHAINZ) - #423

### Contributors

* @toolCHAINZ

## [0.9.7](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.6...z3-sys-v0.9.7) - 2025-08-19

### Added

- add string comparison APIs ([#386](https://github.com/prove-rs/z3.rs/pull/386)) (by @mehrad31415) - #386

### Contributors

* @mehrad31415

## [0.9.6](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.5...z3-sys-v0.9.6) - 2025-08-14

### Added

- add bundled path override ([#408](https://github.com/prove-rs/z3.rs/pull/408)) (by @toolCHAINZ)

### Contributors

* @toolCHAINZ

## [0.9.5](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.4...z3-sys-v0.9.5) - 2025-08-06

### Added

- Bump to Rust 2024 edition ([#381](https://github.com/prove-rs/z3.rs/pull/381)) (by @Evian-Zhang) - #381

### Contributors

* @Evian-Zhang

## [0.9.4](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.3...z3-sys-v0.9.4) - 2025-07-17

### Added

- Add Z3_LIBRARY_PATH_OVERRIDE ([#377](https://github.com/prove-rs/z3.rs/pull/377)) (by @Evian-Zhang) - #377

### Fixed

- use zip instead of deprecated zip-extract ([#380](https://github.com/prove-rs/z3.rs/pull/380)) (by @toolCHAINZ) - #380

### Contributors

* @toolCHAINZ
* @Evian-Zhang

## [0.9.3](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.2...z3-sys-v0.9.3) - 2025-07-14

### Fixed

- narrow build flag impact of wasm fix ([#362](https://github.com/prove-rs/z3.rs/pull/362)) (by @toolCHAINZ) - #362

### Other

- github action updates and caching ([#368](https://github.com/prove-rs/z3.rs/pull/368)) (by @toolCHAINZ) - #368

### Contributors

* @toolCHAINZ

## [0.9.2](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.1...z3-sys-v0.9.2) - 2025-07-12

### Fixed

- fix bundled compilation on wasm with cc >= 1.2 ([#360](https://github.com/prove-rs/z3.rs/pull/360))

## [0.9.1](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.9.0...z3-sys-v0.9.1) - 2025-07-10

### Added

- add gh-release feature to get z3 from released libraries ([#352](https://github.com/prove-rs/z3.rs/pull/352))

### Other

- add note to z3-sys about gh-release rate-limit throttling
- use authenticated requests to pull z3 releases ([#359](https://github.com/prove-rs/z3.rs/pull/359))

## [0.9.0](https://github.com/prove-rs/z3.rs/compare/z3-sys-v0.8.1...z3-sys-v0.9.0) - 2025-07-10

### Other

- Update crate READMEs to use `cargo add` and update example to not require updating for every version change
- upgrade packages and z3 version ([#349](https://github.com/prove-rs/z3.rs/pull/349))
- Fix CI ([#329](https://github.com/prove-rs/z3.rs/pull/329))
- Update bundled sources to Z3 4.13.3 ([#315](https://github.com/prove-rs/z3.rs/pull/315))
- Expose sequence sort and AST ([#310](https://github.com/prove-rs/z3.rs/pull/310))
- Update to bindgen 0.70 ([#312](https://github.com/prove-rs/z3.rs/pull/312))
- Add some missing backticks to some comments.
- Update Z3 to 4.13.2 and update emscripten to `latest` ([#309](https://github.com/prove-rs/z3.rs/pull/309))
- Support for more regular expression operations ([#275](https://github.com/prove-rs/z3.rs/pull/275))
- Fix windows debug builds ([#295](https://github.com/prove-rs/z3.rs/pull/295))
- Update bundled Z3 to z3 4.13.0.
- Improve markdown formatting.
- Fix `doc_markdown` lint.
- Update a test to be less specific.
- Fix two typos.
- Use `pkg-config` when using system libs.
- Update `bindgen` from `0.68` to `0.69`.
- Add more recent regular expression func bindings.
- Bind `Z3_optimize_assert_and_track`.
- Add doc comment to Z3_solver_get_unsat_core.
- Add a warning when `static-link-z3` is used.
- Rename `static-link-z3` to `bundled`.
- Minor tweaks.
- Update to bindgen 0.68 from 0.66
- Link against C++ std lib.
- Improve `Z3_fpa_*` intradoc linking.
- Remove usage of `extern crate`.
- Missing "See also" header.
- Inline format args.
- Add vcpkg support and corresponding CI. ([#251](https://github.com/prove-rs/z3.rs/pull/251))
- Enable `doc_markdown` lint.
