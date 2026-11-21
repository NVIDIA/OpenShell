# @nvidia/openshell-sdk (moved)

> [!IMPORTANT]
> The TypeScript SDK moved to **[ai-openshell/sdk-typescript](https://github.com/ai-openshell/sdk-typescript)**.
> The package is now [`@ai-openshell/sdk`](https://www.npmjs.com/package/@ai-openshell/sdk) on npmjs.org.

`@nvidia/openshell-sdk` is deprecated and contains no SDK code. Each release depends on `@ai-openshell/sdk` from the same minor version line and re-exports it, including `@nvidia/openshell-sdk/raw`, so existing imports keep working. Open issues and pull requests for the SDK in [ai-openshell/sdk-typescript](https://github.com/ai-openshell/sdk-typescript).

## Migrating

The API is unchanged; only the package name is new. The new package is on npmjs.org, so it needs no GitHub Packages token or `.npmrc` scope entry. Replace the dependency, then rewrite the imports:

```shell
npm uninstall @nvidia/openshell-sdk
npm install @ai-openshell/sdk
grep -rlE --exclude-dir=node_modules '@nvidia/openshell-sdk' . | xargs perl -pi -e 's#\@nvidia/openshell-sdk#\@ai-openshell/sdk#g'
```

SDK releases follow core releases, so SDK `X.Y.Z` works with a gateway from OpenShell `vX.Y.Z`. The move is tracked in [#5480](https://github.com/NVIDIA/OpenShell/issues/5480).
