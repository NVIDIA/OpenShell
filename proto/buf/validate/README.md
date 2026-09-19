# Vendored Protovalidate schema

`validate.proto` is the shared annotation schema used by every OpenShell
protobuf generator. It is vendored once because Rust and Python invoke
`protoc` directly while Go and TypeScript use Buf.

The schema body comes from `prost-protovalidate-types` 0.6.0, repository
commit `90b6d55997fd3a14dbb1611d4677aaaf583a34d4`. Keep its declarations aligned
with that pinned Rust runtime when updating either dependency. The SPDX lines
prepended for repository license checks are the only local additions.

The upstream file is Copyright 2023-2026 Buf Technologies, Inc. and licensed
under Apache-2.0, as recorded in its header.
