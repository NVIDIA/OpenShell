# Profiles

Accessor: `client.Providers().Profiles()`

Manage provider profiles for AI model providers. Profiles define connection details,
credentials, and model mappings for providers like OpenAI, Anthropic, or custom endpoints.

## List

List all provider profiles visible to the current user.

```go
profiles, err := client.Providers().Profiles().List(ctx, "default")
if err != nil {
    log.Fatal(err)
}
for _, p := range profiles {
    fmt.Printf("Profile: %s (%s)\n", p.ID, p.DisplayName)
}
```

## Import

Import one or more provider profiles from configuration items.

```go
result, err := client.Providers().Profiles().Import(ctx, "default", []v1.ProfileImportItem{
    {
        Profile: v1.ProviderProfile{
            DisplayName: "OpenAI",
            Category:    v1.ProfileCategoryInference,
        },
        Source: "manual",
    },
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Imported: %v\n", result.Imported)
```

## Update

Update a profile using optimistic concurrency control via the resource version.

```go
profile, err := client.Providers().Profiles().Get(ctx, "default", "profile-id")
if err != nil {
    log.Fatal(err)
}

profile.DisplayName = "Updated Provider"
result, err := client.Providers().Profiles().Update(
    ctx, "default",
    profile.ID,
    profile.ResourceVersion,
    v1.ProfileImportItem{Profile: *profile, Source: "manual"},
)
if err != nil {
    // See [Error Handling](../error-handling.md) for conflict errors
    log.Fatal(err)
}
```

## Lint

Validate profile configurations without persisting them. Useful for pre-flight checks.

```go
items := []v1.ProfileImportItem{
    {
        Profile: v1.ProviderProfile{DisplayName: "Test"},
        Source:  "manual",
    },
}
result, err := client.Providers().Profiles().Lint(ctx, "default", items)
if err != nil {
    log.Fatal(err)
}
for _, d := range result.Diagnostics {
    fmt.Printf("[%s] %s: %s\n", d.Severity, d.Field, d.Message)
}
```

See also: [Error Handling](../error-handling.md), [Testing](../testing.md)
