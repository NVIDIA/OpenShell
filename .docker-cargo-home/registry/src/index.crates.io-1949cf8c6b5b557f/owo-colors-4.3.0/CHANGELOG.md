# Changelog

## [4.3.0] - 2026-02-22

### Fixed

- Scripts in the `scripts/` directory are no longer published in the crate package. Thanks [weiznich](https://github.com/owo-colors/owo-colors/pull/152) for your first contribution!

### Changed

- Mark methods with `#[rust_analyzer::completions(ignore_flyimport)]` and the `OwoColorize` trait with `#[rust_analyzer::completions(ignore_flyimport_methods)]`. This prevents owo-colors methods from being completed with rust-analyzer unless the `OwoColorize` trait is included.

  Unfortunately, this also breaks explicit autocomplete commands such as Ctrl-Space in many editors. (The language server protocol doesn't appear to have a way to differentiate between implicit and explicit autocomplete commands.) On balance we believe this is the right approach, but please do provide feedback on [PR #141](https://github.com/owo-colors/owo-colors/pull/141) if it negatively affects you.
- Updated MSRV to Rust 1.81.

## [4.2.3] - 2025-09-29

### Fixed

Replaced obsolete `doc_auto_cfg` with `doc_cfg`, to fix Rust nightly builds with the `doc_cfg` flag enabled.

## [4.2.2] - 2025-06-23

### Fixed

Fixed applying a background color and a text effect (like underline or italic) at the same time ([#145]).

[#145]: https://github.com/owo-colors/owo-colors/issues/145

## [4.2.1] - 2025-05-15

### Fixed

- Fixed a couple of bugs while rendering custom colors ([#144]). Thanks [https://github.com/MiguelValentine](@MiguelValentine) for your first contribution!

[#144]: https://github.com/owo-colors/owo-colors/pull/144

## [4.2.0] - 2025-02-22

### Added

- `Style::prefix_formatter` and `Style::suffix_formatter` return `Display` formatters for the prefix and the suffix of a style, respectively.
- All the `*Display` types now have an `into_styled` function that converts those types into a `Styled`, erasing type parameters.
- Even more methods are now `const`.

### Changed

- The `Color` and `DynColor` traits are now explicitly marked sealed (i.e. downstream crates cannot implement them).

  These traits were already effectively sealed due to a number of hidden methods that were not part of the API, but they are now explicitly so. In that sense this is not a breaking change, so it's being released under a new minor version rather than a major version.

## [4.1.1] - 2025-02-22

### Added

- The vast majority of owo-colors is now usable in const contexts.

### Fixed

- Documentation for `Stream` is now rendered properly. Thanks [purplesyringa](https://github.com/purplesyringa) for the contribution!
- Replace brittle const-promotion-based unsafe code with safe code. Thanks [Manish](https://github.com/Manishearth) for the contribution!

### Other

- owo-colors now lives under its own organization, https://github.com/owo-colors.

[4.3.0]: https://github.com/owo-colors/owo-colors/releases/tag/v4.3.0
[4.2.3]: https://github.com/owo-colors/owo-colors/releases/tag/v4.2.3
[4.2.2]: https://github.com/owo-colors/owo-colors/releases/tag/v4.2.2
[4.2.1]: https://github.com/owo-colors/owo-colors/releases/tag/v4.2.1
[4.2.0]: https://github.com/owo-colors/owo-colors/releases/tag/v4.2.0
[4.1.1]: https://github.com/owo-colors/owo-colors/releases/tag/v4.1.1

For information about earlier versions, see [the commit history](https://github.com/jam1garner/owo-colors/commits/master).
