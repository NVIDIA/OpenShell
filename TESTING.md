# Testing

## Running Tests

```bash
mise run test          # Rust + Python unit tests
mise run e2e           # End-to-end tests (starts a Docker-backed gateway)
mise run ci            # Everything: lint, compile checks, and tests
```

## Test Layout

```text
crates/*/src/          # Inline #[cfg(test)] modules
crates/*/tests/        # Rust integration tests
python/openshell/      # Python unit tests (*_test.py suffix)
e2e/python/            # Python E2E tests (test_*.py prefix)
e2e/rust/              # Rust CLI E2E tests
```

## Rust Tests

Unit tests live inline with `#[cfg(test)] mod tests` blocks. Integration tests
go in `crates/*/tests/` and are named `*_integration.rs`.

Use `#[tokio::test]` for anything async:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_round_trip() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store.put("sandbox", "abc", "my-sandbox", b"payload").await.unwrap();
        let record = store.get("sandbox", "abc").await.unwrap().unwrap();
        assert_eq!(record.payload, b"payload");
    }
}
```

Run Rust tests only:

```bash
mise run test:rust     # cargo test --workspace
```

## Python Unit Tests

Python unit tests use the `*_test.py` suffix convention (not `test_*` prefix)
and live alongside the source in `python/openshell/`. They use mock-based
patterns with fake gRPC stubs:

```python
def test_exec_python_serializes_callable_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    def add(a: int, b: int) -> int:
        return a + b

    result = client.exec_python("sandbox-1", add, args=(2, 3))
    assert result.exit_code == 0
```

Run Python unit tests only:

```bash
mise run test:python   # uv run pytest python/
```

## E2E Tests

E2E tests run against a live gateway. By default, `mise run e2e` starts an
ephemeral standalone gateway with the Docker compute driver, runs the suite,
and cleans it up afterward. To run the suite against an existing plaintext
gateway, set `OPENSHELL_GATEWAY_ENDPOINT`:

```bash
OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:18080 mise run e2e
```

Raw endpoint mode is HTTP-only. Use a named gateway config when a gateway
requires mTLS.

### Python E2E (`e2e/python/`)

Tests use the `sandbox` fixture from `conftest.py` to create real sandboxes:

```python
def test_exec_returns_stdout(sandbox):
    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec(["echo", "hello"])
        assert result.exit_code == 0
        assert "hello" in result.stdout
```

#### `Sandbox.exec_python`

`exec_python` serializes a Python callable with `cloudpickle`, sends it to the
sandbox, and returns the result. Because cloudpickle serializes module-level
functions by reference (which fails inside the sandbox), use one of these
patterns:

**Closures from factory functions:**

```python
def _make_adder():
    def add(a, b):
        return a + b
    return add

def test_addition(sandbox):
    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(_make_adder(), args=(2, 3))
        assert result.stdout.strip() == "5"
```

**Bound methods on local classes:**

```python
def test_multiply(sandbox):
    class Calculator:
        def multiply(self, a, b):
            return a * b

    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(Calculator().multiply, args=(6, 7))
        assert result.stdout.strip() == "42"
```

#### Shared Fixtures (`e2e/python/conftest.py`)

| Fixture | Scope | Purpose |
|---|---|---|
| `sandbox_client` | session | gRPC client connected to the active gateway |
| `sandbox` | function | Factory returning a `Sandbox` context manager |
| `inference_client` | session | Client for managing inference routes |
| `mock_inference_route` | session | Creates a mock OpenAI-protocol route for tests |

### Rust CLI E2E (`e2e/rust/`)

Rust-based e2e tests that exercise the `openshell` CLI binary as a subprocess.
They live in the `openshell-e2e` crate and use a shared harness for sandbox
lifecycle management, output parsing, and cleanup.

Suites:

- Common suite (`--features e2e`) - driver-neutral CLI behavior, sandbox lifecycle, sync, port forwarding, policy, and provider tests.
- Docker suite (`--features e2e-docker`) - common suite plus Docker-only coverage such as Dockerfile image builds, Docker preflight checks, and managed Docker gateway resume.
- Docker GPU suite (`--features e2e-docker-gpu`) - Docker suite plus GPU sandbox smoke coverage.

Run the Docker-backed Rust CLI e2e suite:

```shell
mise run e2e:rust
```

Run the Podman-backed Rust CLI e2e suite:

```shell
mise run e2e:podman
```

Run a single test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test sync
```

Run a single Docker-only test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test custom_image
```

The harness (`e2e/rust/src/harness/`) provides:

| Module | Purpose |
|---|---|
| `binary` | Builds and resolves the `openshell` binary from the workspace |
| `container` | Container-engine selection and support containers for proxy tests |
| `gateway` | Managed gateway restart controls for gateway-owned e2e runs |
| `sandbox` | `SandboxGuard` RAII type — creates sandboxes and deletes them on drop |
| `output` | ANSI stripping and field extraction from CLI output |
| `port` | `wait_for_port()` and `find_free_port()` for TCP testing |

## Environment Variables

| Variable | Purpose |
|---|---|
| `OPENSHELL_GATEWAY` | Override active gateway name for E2E tests |
| `OPENSHELL_GATEWAY_ENDPOINT` | Run E2E tests against an existing plaintext HTTP gateway endpoint |
| `OPENSHELL_E2E_DRIVER` | Driver name exported by the e2e gateway wrapper (`docker`, `podman`, or `vm`) |
