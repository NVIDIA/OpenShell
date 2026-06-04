# CLI Architecture

The OpenShell CLI (`openshell`) provides a command-line interface for managing sandboxes, gateways, providers, and policies.

## Component Overview

| Component | Path | Purpose |
|-----------|------|---------|
| Main entry point | `crates/openshell-cli/src/main.rs` | CLI argument parsing, command routing |
| Command implementations | `crates/openshell-cli/src/run.rs` | Core command logic |
| Output formatting | `crates/openshell-cli/src/output.rs` | Generic output format helpers |

## Output Formatting

Many CLI commands support the `--output` flag, allowing users to specify output format as JSON, YAML, or table. The `output` module provides generic helper functions to eliminate duplication across commands.

### Design

**Early-return pattern:** Helper functions return `Result<bool>`:
- `Ok(true)` — Format was handled (json/yaml), caller should return immediately
- `Ok(false)` — Format is "table", caller should continue to table rendering
- `Err(e)` — Unsupported format or serialization error

**Available functions:**

- `print_output_collection<T, F>(format, items, to_json)` — Format collections
- `print_output_single<T, F>(format, item, to_json)` — Format single items
- `print_output_direct(format, json_fn, yaml_fn)` — Format pre-formatted strings
- `*_to_writer()` variants — Output to custom writers instead of stdout

### Usage Pattern

```rust
use crate::output::print_output_collection;

pub fn sandbox_list(output: &str) -> Result<()> {
    let sandboxes = fetch_sandboxes()?;
    
    // Handle json/yaml output with early return
    if print_output_collection(output, &sandboxes, sandbox_to_json)? {
        return Ok(());
    }
    
    // Fall through to table rendering for "table" format
    render_sandbox_table(&sandboxes);
    Ok(())
}

fn sandbox_to_json(sandbox: &Sandbox) -> serde_json::Value {
    serde_json::json!({
        "id": sandbox.id,
        "name": sandbox.name,
        "status": sandbox.status,
    })
}
```

### Behavioral Details

- **JSON output:** Uses `println!()` — includes trailing newline
- **YAML output:** Uses `print!()` — no trailing newline (`serde_yml` includes one)
- **Error handling:** All serialization errors wrapped with `.into_diagnostic()` for miette compatibility
- **Type flexibility:** Format parameter accepts `impl AsRef<str>` for both `&str` and enum types

### Adding Output Support to New Commands

1. Accept an `output: &str` parameter (or use the `OutputFormat` enum from `main.rs`)
2. Write a converter function: `fn item_to_json(item: &Item) -> serde_json::Value`
3. Call the appropriate helper with early-return pattern
4. Implement table rendering for the "table" format

See `gateway_list()` (line 1292) and `sandbox_list()` (line 3166) in `src/run.rs` for examples.

## Commands Using Output Formatting

| Command | Lines | Helper Used | Converter Function |
|---------|-------|-------------|-------------------|
| `gateway list` | ~1290 | `print_output_collection` | `gateway_to_json` |
| `sandbox list` | ~3166 | `print_output_collection` | `sandbox_to_json` |
| `provider list-profiles` | ~4647 | `print_output_direct` | External crate functions |
| `provider profile export` | ~4701 | `print_output_direct` | External crate functions |

Policy commands (`sandbox policy get`, etc.) use writer-based variants for custom output destinations.
