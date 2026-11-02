# Python SDK implementation

The synchronous clients in `openshell/sandbox.py` and `openshell/providers.py`
own request construction and response conversion. `tasks/scripts/generate_python_async.py`
emits concrete async counterparts into `openshell/aio.py`; the handwritten
`openshell/_async_runtime.py` owns asyncio transport, authentication, pagination,
and resource cleanup. Generated files are build outputs and are not committed.

Run `mise run python:proto` after changing client methods or protobufs. The same
generation runs when building release wheels. The async transform recognizes
stub calls, lazy pager fetches, stream iteration, and polling sleeps. Add new I/O
shapes explicitly to the generator and test their runtime and consumer typing
contracts. Keep blocking operations out of generated async method bodies.

Validate changes with Python formatting, lint, and type checks plus the affected
tests. `python/openshell/async_client_test.py` exercises real loopback gRPC calls;
`python/grpc_typing_test.py` checks consumer signatures. The wheel verifier requires
both generated bindings and the async client module.
