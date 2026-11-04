# OpenShell SDK for Go (moved)

> [!IMPORTANT]
> The Go SDK moved to **[ai-openshell/sdk-go](https://github.com/ai-openshell/sdk-go)**.
> The module path is now `github.com/ai-openshell/sdk-go`.

This directory is frozen and will be removed from NVIDIA/OpenShell. Its last tagged version, `github.com/NVIDIA/OpenShell/sdk/go`, is marked deprecated and gets no further changes. Open issues and pull requests for the SDK in [ai-openshell/sdk-go](https://github.com/ai-openshell/sdk-go).

## Migrating

Packages and APIs are unchanged; only the module path is new. Rewrite the imports, then fetch the new module:

```shell
grep -rl --include='*.go' --include=go.mod 'github.com/NVIDIA/OpenShell/sdk/go' . | xargs perl -pi -e 's#github.com/NVIDIA/OpenShell/sdk/go#github.com/ai-openshell/sdk-go#g'
go get github.com/ai-openshell/sdk-go@latest && go mod tidy
```

SDK releases follow core releases, so SDK `vX.Y.Z` works with core `vX.Y.Z`. The move is tracked in [#5031](https://github.com/NVIDIA/OpenShell/issues/5031).
