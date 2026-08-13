# Refresh

Accessor: `client.Providers().Refresh()`

Manage credential refresh schedules for provider profiles. Configure automatic
rotation of API keys and monitor refresh status.

## GetStatus

Check the refresh status for a specific provider credential.

```go
statuses, err := client.Providers().Refresh().GetStatus(ctx, "default", "openai", "default")
if err != nil {
    log.Fatal(err)
}
for _, s := range statuses {
    fmt.Printf("Key: %s, Last refresh: %s, Next: %s\n",
        s.CredentialKey, s.LastRefreshAt, s.NextRefreshAt)
}
```

## Configure

Set up automatic credential refresh with a defined strategy and material.

```go
status, err := client.Providers().Refresh().Configure(ctx, "default", &v1.RefreshConfig{
    Provider:      "openai",
    CredentialKey:  "default",
    Strategy:       v1.RefreshStrategyOAuth2ClientCredentials,
    Material: map[string]string{
        "client_id":     "my-client-id",
        "client_secret": "my-client-secret",
        "token_url":     "https://oauth.example.com/token",
    },
    SecretMaterialKeys: []string{"client_secret"},
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Refresh configured, next rotation: %s\n", status.NextRefreshAt)
```

## Rotate

Manually trigger an immediate credential rotation.

```go
status, err := client.Providers().Refresh().Rotate(ctx, "default", "openai", "default")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Rotated successfully at %s\n", status.LastRefreshAt)
```

See also: [Error Handling](../error-handling.md), [Profiles](profiles.md)
