# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.15](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.14...z3-v0.19.15) - 2026-03-19

### Added

- Implement Optimize Convenience Methods ([#520](https://github.com/prove-rs/z3.rs/pull/520)) (by @toolCHAINZ) - #520

### Fixed

- {Solver, Optimize}::check_and_get_model no longer take ownership ([#522](https://github.com/prove-rs/z3.rs/pull/522)) (by @toolCHAINZ) - #522

### Other

- add missing docs for Boolean operators and pseudo-boolean constraints ([#527](https://github.com/prove-rs/z3.rs/pull/527)) (by @matth2k) - #527
- add missing doc comments for Solver::eval() and several Ast impls ([#526](https://github.com/prove-rs/z3.rs/pull/526)) (by @matth2k) - #526
- Optimize::get_assertions ([#523](https://github.com/prove-rs/z3.rs/pull/523)) (by @toolCHAINZ) - #523

### Contributors

* @matth2k
* @toolCHAINZ

## [0.19.14](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.13...z3-v0.19.14) - 2026-03-13

### Other

- internal refactoring of datatype builder ([#517](https://github.com/prove-rs/z3.rs/pull/517)) (by @toolCHAINZ) - #517

### Contributors

* @toolCHAINZ

## [0.19.13](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.12...z3-v0.19.13) - 2026-03-06

### Other

- updated the following local packages: z3-sys

## [0.19.12](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.11...z3-v0.19.12) - 2026-03-04

### Added

- add `with` method to Tactic ([#511](https://github.com/prove-rs/z3.rs/pull/511)) (by @longlinh123456) - #511

### Contributors

* @longlinh123456

## [0.19.11](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.10...z3-v0.19.11) - 2026-02-27

### Added

- add high-level API for model sorts/sort universes ([#506](https://github.com/prove-rs/z3.rs/pull/506)) (by @toolCHAINZ) - #506

### Fixed

- standardize AstVector display/debug impl ([#508](https://github.com/prove-rs/z3.rs/pull/508)) (by @toolCHAINZ) - #508

### Other

- FusedIterator and ExactSizeIterator for model/SortIter ([#509](https://github.com/prove-rs/z3.rs/pull/509)) (by @toolCHAINZ) - #509

### Contributors

* @toolCHAINZ

## [0.19.10](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.9...z3-v0.19.10) - 2026-02-24

### Added

- algebraic numbers, polynomials, enhanced floats, AST vectors, and quantifier elimination ([#500](https://github.com/prove-rs/z3.rs/pull/500)) (by @toolCHAINZ, @NikolajBjorner) - #500

### Contributors

* @toolCHAINZ
* @NikolajBjorner

## [0.19.9](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.8...z3-v0.19.9) - 2026-02-21

### Other

- expand build flag documentation ([#499](https://github.com/prove-rs/z3.rs/pull/499)) (by @toolCHAINZ) - #499

### Contributors

* @toolCHAINZ

## [0.19.8](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.7...z3-v0.19.8) - 2026-02-13

### Other

- updated the following local packages: z3-sys

## [0.19.7](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.6...z3-v0.19.7) - 2025-12-27

### Added

- Add check_and_get_model method to Solver ([#484](https://github.com/prove-rs/z3.rs/pull/484)) (by @toolCHAINZ) - #484

### Contributors

* @toolCHAINZ

## [0.19.6](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.5...z3-v0.19.6) - 2025-12-10

### Added

- impl Sum and Product for Int and Real ([#479](https://github.com/prove-rs/z3.rs/pull/479)) (by @toolCHAINZ) - #479

### Contributors

* @toolCHAINZ

## [0.19.5](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.4...z3-v0.19.5) - 2025-11-20

### Other

- remove unused imports in z3::ast and use absolute paths in macros ([#471](https://github.com/prove-rs/z3.rs/pull/471)) (by @lixitrixi) - #471

### Contributors

* @lixitrixi

## [0.19.4](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.3...z3-v0.19.4) - 2025-11-17

### Other

- updated the following local packages: z3-sys

## [0.19.3](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.2...z3-v0.19.3) - 2025-11-16

### Added

- Implement support for bundling z3 without use of github checkout ([#464](https://github.com/prove-rs/z3.rs/pull/464)) (by @ThomasTNO) - #464

### Contributors

* @ThomasTNO

## [0.19.2](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.1...z3-v0.19.2) - 2025-10-21

### Added

- Add `Datatype::update_field`, `FuncDecl::domain`, `FuncDecl::range` ([#455](https://github.com/prove-rs/z3.rs/pull/455)) (by @willcrichton) - #455
- impl Default for Solver, Optimize, and Parser ([#456](https://github.com/prove-rs/z3.rs/pull/456)) (by @toolCHAINZ) - #456

### Contributors

* @willcrichton
* @toolCHAINZ

## [0.19.1](https://github.com/prove-rs/z3.rs/compare/z3-v0.19.0...z3-v0.19.1) - 2025-09-26

### Added

- allow context closures to capture non-Sync data ([#452](https://github.com/prove-rs/z3.rs/pull/452)) (by @gmorenz) - #452

### Contributors

* @gmorenz

## [0.19.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.18.2...z3-v0.19.0) - 2025-09-26

### Added

- impl Translate for FuncDecl ([#439](https://github.com/prove-rs/z3.rs/pull/439)) (by @toolCHAINZ) - #439
- Special Binary Relation FuncDecls ([#340](https://github.com/prove-rs/z3.rs/pull/340)) (by @grahnen) - #340

### Changed

- Fallible z3-sys APIs now return Option<NonNull<T>> ([#450](https://github.com/prove-rs/z3.rs/pull/450)) (by @toolCHAINZ) - #450

### Other

- fix typos in example ([#448](https://github.com/prove-rs/z3.rs/pull/448)) (by @toolCHAINZ) - #448

### Removed

- [**breaking**] Context no longer implements Default and Context::new is now private ([#451](https://github.com/prove-rs/z3.rs/pull/451)) (by @toolCHAINZ) - #451

### Contributors

* @toolCHAINZ
* @grahnen

## [0.18.2](https://github.com/prove-rs/z3.rs/compare/z3-v0.18.1...z3-v0.18.2) - 2025-09-10

### Added

- gate newer Z3 APIs behind features ([#444](https://github.com/prove-rs/z3.rs/pull/444)) (by @toolCHAINZ) - #444

### Contributors

* @toolCHAINZ

## [0.18.1](https://github.com/prove-rs/z3.rs/compare/z3-v0.18.0...z3-v0.18.1) - 2025-09-09

### Fixed

- Ast::ne -> Bool is now defined and preferred over PartialEq::ne ([#442](https://github.com/prove-rs/z3.rs/pull/442)) (by @toolCHAINZ) - #442

### Contributors

* @toolCHAINZ

## [0.18.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.17.0...z3-v0.18.0) - 2025-09-08

### Added

- add consuming solutions iterator ([#433](https://github.com/prove-rs/z3.rs/pull/433)) (by @toolCHAINZ) - #433

### Changed

- [**breaking**] APIs accepting `Bool` no longer accept `bool` ([#436](https://github.com/prove-rs/z3.rs/pull/436)) (by @toolCHAINZ) - #436

### Fixed

- Solver::clone preserves tactics and params ([#440](https://github.com/prove-rs/z3.rs/pull/440)) (by @toolCHAINZ) - #440

### Other

- add simple example ([#437](https://github.com/prove-rs/z3.rs/pull/437)) (by @toolCHAINZ) - #437

### Contributors

* @toolCHAINZ

## [0.17.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.16.2...z3-v0.17.0) - 2025-09-03

### Added

- Add the ability to iterate over solutions from a `Solver` ([#431](https://github.com/prove-rs/z3.rs/pull/431)) (by @toolCHAINZ) - #431

### Changed

- [**breaking**] rename `_eq` to `eq` and `*_real_*` to `*_rational_*` ([#305](https://github.com/prove-rs/z3.rs/pull/305)) (by @dragazo) - #305
- deprecate legacy Context APIs ([#427](https://github.com/prove-rs/z3.rs/pull/427)) (by @toolCHAINZ) - #427

### Contributors

* @toolCHAINZ
* @dragazo

## [0.16.2](https://github.com/prove-rs/z3.rs/compare/z3-v0.16.1...z3-v0.16.2) - 2025-08-25

### Other

- updated the following local packages: z3-sys

## [0.16.1](https://github.com/prove-rs/z3.rs/compare/z3-v0.16.0...z3-v0.16.1) - 2025-08-23

### Other

- A first pass at documenting how to define recursive datatypes ([#420](https://github.com/prove-rs/z3.rs/pull/420)) (by @Pat-Lafon) - #420

### Contributors

* @Pat-Lafon

## [0.16.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.15.0...z3-v0.16.0) - 2025-08-21

### Added

- [**breaking**] Use an implicit thread-local z3 context by default ([#417](https://github.com/prove-rs/z3.rs/pull/417)) (by @toolCHAINZ) - #417

### Contributors

* @toolCHAINZ

## [0.15.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.14.4...z3-v0.15.0) - 2025-08-19

### Added

- [**breaking**] trait-based conversions and operations ([#410](https://github.com/prove-rs/z3.rs/pull/410)) (by @toolCHAINZ) - #410

### Other

- add unit tests for rounding modes ([#389](https://github.com/prove-rs/z3.rs/pull/389)) (by @mehrad31415) - #389

### Contributors

* @mehrad31415
* @toolCHAINZ

## [0.14.4](https://github.com/prove-rs/z3.rs/compare/z3-v0.14.3...z3-v0.14.4) - 2025-08-19

### Added

- Add string comparison APIs ([#386](https://github.com/prove-rs/z3.rs/pull/386)) (by @mehrad31415) - #386
- Add Sequence::empty and contains Methods ([#390](https://github.com/prove-rs/z3.rs/pull/390)) (by @mehrad31415) - #390
- Add Constructors for Floating-Point NaN Values ([#392](https://github.com/prove-rs/z3.rs/pull/392)) (by @mehrad31415) - #392

### Other

- Move Model Retrieval Docs ([#394](https://github.com/prove-rs/z3.rs/pull/394)) (by @mehrad31415) - #394

### Contributors

* @mehrad31415

## [0.14.3](https://github.com/prove-rs/z3.rs/compare/z3-v0.14.2...z3-v0.14.3) - 2025-08-18

### Fixed

- decrement vectors after get_consequences is done with them ([#414](https://github.com/prove-rs/z3.rs/pull/414)) (by @Pat-Lafon) - #414

### Other

- reorganize ast module ([#411](https://github.com/prove-rs/z3.rs/pull/411)) (by @toolCHAINZ) - #411

### Contributors

* @Pat-Lafon
* @toolCHAINZ

## [0.14.2](https://github.com/prove-rs/z3.rs/compare/z3-v0.14.1...z3-v0.14.2) - 2025-08-14

### Added

- add bundled path override ([#408](https://github.com/prove-rs/z3.rs/pull/408)) (by @toolCHAINZ)

### Contributors

* @toolCHAINZ

## [0.14.1](https://github.com/prove-rs/z3.rs/compare/z3-v0.14.0...z3-v0.14.1) - 2025-08-09

### Added

- enable moving and referencing z3 types between threads ([#404](https://github.com/prove-rs/z3.rs/pull/404)) (by @toolCHAINZ) - #404
- impl default for context ([#402](https://github.com/prove-rs/z3.rs/pull/402)) (by @toolCHAINZ) - #402

### Contributors

* @toolCHAINZ

## [0.14.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.13.3...z3-v0.14.0) - 2025-08-06

### Added

- add BV::from_bits  ([#398](https://github.com/prove-rs/z3.rs/pull/398)) (by @Evian-Zhang) - #398
- Bump to Rust 2024 edition ([#381](https://github.com/prove-rs/z3.rs/pull/381)) (by @Evian-Zhang) - #381

### Changed

- [**breaking**] refcount z3 context ([#401](https://github.com/prove-rs/z3.rs/pull/401)) (by @toolCHAINZ) - #401

### Fixed

- [**breaking**] make argument of `Probe::lt` consistent with other comparison operations (by @mehrad31415) - #391
- make BV::from_bits return Option ([#399](https://github.com/prove-rs/z3.rs/pull/399)) (by @toolCHAINZ) - #399

### Contributors

* @toolCHAINZ
* @Evian-Zhang
* @mehrad31415

## [0.13.3](https://github.com/prove-rs/z3.rs/compare/z3-v0.13.2...z3-v0.13.3) - 2025-07-17

### Added

- Add Z3_LIBRARY_PATH_OVERRIDE ([#377](https://github.com/prove-rs/z3.rs/pull/377)) (by @Evian-Zhang) - #377

### Contributors

* @Evian-Zhang

## [0.13.2](https://github.com/prove-rs/z3.rs/compare/z3-v0.13.1...z3-v0.13.2) - 2025-07-14

### Fixed

- Make translate 'dst lifetime independent of 'ctx ([#365](https://github.com/prove-rs/z3.rs/pull/365)) (by @toolCHAINZ) - #365

### Other

- Better documentation of z3 installation options ([#364](https://github.com/prove-rs/z3.rs/pull/364)) (by @lmondada) - #364

### Contributors

* @toolCHAINZ
* @lmondada

## [0.13.1](https://github.com/prove-rs/z3.rs/compare/z3-v0.13.0...z3-v0.13.1) - 2025-07-10

### Added

- add gh-release feature to get z3 from released libraries ([#352](https://github.com/prove-rs/z3.rs/pull/352))

## [0.13.0](https://github.com/prove-rs/z3.rs/compare/z3-v0.12.1...z3-v0.13.0) - 2025-07-10

### Added

- atmost and atleast ([#320](https://github.com/prove-rs/z3.rs/pull/320))

### Other

- Update crate READMEs to use `cargo add` and update example to not require updating for every version change
- Fix `mismatched_lifetime_syntaxes` lints ([#354](https://github.com/prove-rs/z3.rs/pull/354))
- Fix some `clippy::uninlined_format_args` lints ([#353](https://github.com/prove-rs/z3.rs/pull/353))
- Panic through rust if provided an invalid tactic str to prevent SIGSEGV ([#339](https://github.com/prove-rs/z3.rs/pull/339))
- Add is_infinite, is_normal, is_subnormal, is_zero, is_nan to Float ([#336](https://github.com/prove-rs/z3.rs/pull/336))
- Make `z3_ctx` `pub` ([#341](https://github.com/prove-rs/z3.rs/pull/341))
- Fix CI ([#329](https://github.com/prove-rs/z3.rs/pull/329))
- Add high-level binding for quantifier creation with additional attributes ([#326](https://github.com/prove-rs/z3.rs/pull/326))
- Add bindings for seq.++ and seq.unit ([#323](https://github.com/prove-rs/z3.rs/pull/323))
- Adjust lifetimes on `ModelIter` to make them more permissive ([#324](https://github.com/prove-rs/z3.rs/pull/324))
- Add binding for FPA to IEEE-754 bit-vector ([#322](https://github.com/prove-rs/z3.rs/pull/322))
- Add binding for str.substr ([#321](https://github.com/prove-rs/z3.rs/pull/321))
- Add binding to get unit string at index ([#319](https://github.com/prove-rs/z3.rs/pull/319))
- Add high-level binding for string length ([#318](https://github.com/prove-rs/z3.rs/pull/318))
- Expose sequence sort and AST ([#310](https://github.com/prove-rs/z3.rs/pull/310))
- Add high-level binding to create lambda consts ([#311](https://github.com/prove-rs/z3.rs/pull/311))
- Support consequences API ([#302](https://github.com/prove-rs/z3.rs/pull/302)) ([#308](https://github.com/prove-rs/z3.rs/pull/308))
- Real approx functions ([#304](https://github.com/prove-rs/z3.rs/pull/304))
- Z3 Optimize: add `assert_and_track` and `get_unsat_core` ([#300](https://github.com/prove-rs/z3.rs/pull/300))
- Support for more regular expression operations ([#275](https://github.com/prove-rs/z3.rs/pull/275))
- Expose underlying Z3_context and Z3_sort ([#298](https://github.com/prove-rs/z3.rs/pull/298))
- Expose Z3_get_version in the high-level interface
- [deps] Bump env_logger to 0.11
- add parameter configuration API
- add new_const and fresh_const functions to Dynamic
- fix array_range and array_domain lifetimes
- Fix doc comment typo.
- Implement += for Solver
- Expose API to convert solver into SMT-LIB2 format ([#267](https://github.com/prove-rs/z3.rs/pull/267))
- Add doc comment to Z3_solver_get_unsat_core.
- Add a warning when `static-link-z3` is used.
- Rename `static-link-z3` to `bundled`.
- Fix `semicolon_if_nothing_returned` lints.
- Fix lifetime on `Solver::get_assertions()` result.
- Implement `ast::Float::as_f64`
- Remove usage of `extern crate`.
- Always use `num`, remove `arbitrary-size-numeral` feature.
- Update to Rust edition 2018. Collapse some imports.
- Inline format args.
- Add vcpkg support and corresponding CI. ([#251](https://github.com/prove-rs/z3.rs/pull/251))
- Enable `doc_markdown` lint.
- Fix typo: "sufix" -> "suffix"
- Add backticks around logic expression.
- Add is_const_array
- Have distinct take impl Borrow
- Fix clippy::doc_markdown warnings.
- Fix redundant_pattern_matching warning.
- Add comment
- Use Borrow in varop arrays
- Check Kind for optimize maximize
