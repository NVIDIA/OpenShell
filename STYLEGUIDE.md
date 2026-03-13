# STYLE_GUIDE

## License Headers

All source files must include SPDX copyright headers.

```bash
# Add/update headers
mise run license:update

# Check headers
mise run license:check
```

## Code Style

- Rust: format with `rustfmt`, lint with Clippy.
- Python: format and lint with `ruff`, type-check with `ty`.

Recommended workflow before opening a PR:

```bash
mise run fmt
mise run lint
mise run ci
```

## CLI Output Style

When printing structured CLI output:

- Add a blank line after headings.
- Indent key-value fields by 2 spaces.
- Use dimmed labels for field keys (for example, `"Id:".dimmed()`).
- Use cyan + bold for primary headings.

Good:

```text
Created sandbox:

  Id: cddeeb6d-a4d3-4158-a4d1-bd931f743700
  Name: sandbox-cddeeb6d
  Namespace: openshell
```

Bad:

```text
Created sandbox:
  Id: cddeeb6d-a4d3-4158-a4d1-bd931f743700
  Name: sandbox-cddeeb6d
  Namespace: openshell
```
