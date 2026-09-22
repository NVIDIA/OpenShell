# Policy

Accessor: `client.Policy()`

Manage network policies for sandboxes through a draft-based workflow. Policies
go through a draft, review, and approval cycle before being applied.

## GetDraft

Retrieve the current draft policy for a sandbox.

```go
draft, err := client.Policy().GetDraft(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
for _, chunk := range draft.Chunks {
    fmt.Printf("Chunk %s: rule=%s, status=%s, confidence=%.1f\n",
        chunk.ID, chunk.RuleName, chunk.Status, chunk.Confidence)
}
```

## ApproveAllDraftChunks

Approve all pending chunks in a single operation.

```go
result, err := client.Policy().ApproveAllDraftChunks(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Approved %d chunks (skipped %d), policy version: %d\n",
    result.ChunksApproved, result.ChunksSkipped, result.PolicyVersion)
```

## GetStatus

Check the current policy enforcement status for a sandbox.

```go
status, err := client.Policy().GetStatus(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Active version: %d, revision status: %s\n",
    status.ActiveVersion, status.Revision.Status)
```

## List

`List` returns a lazy pager over policy revisions for one sandbox. Use
`ListAll` to collect every page.

```go
revisions, err := client.Policy().ListAll(ctx, "default", "my-sandbox")
if err != nil {
    log.Fatal(err)
}
for _, rev := range revisions {
    fmt.Printf("Version %d: %s (status: %s)\n",
        rev.Version, rev.CreatedAt, rev.Status)
}
```

## RejectDraftChunk

Reject a specific draft chunk, providing a reason.

```go
err := client.Policy().RejectDraftChunk(ctx, "default", "my-sandbox", "chunk-abc", "Too permissive")
if err != nil {
    log.Fatal(err)
}
```

## EditDraftChunk

Modify the proposed rule in a draft chunk before approval.

```go
err := client.Policy().EditDraftChunk(ctx, "default", "my-sandbox", "chunk-abc", &v1.NetworkPolicyRule{
    Name: "allow-api",
    Endpoints: []v1.PolicyNetworkEndpoint{{
        Host:     "api.example.com",
        Port:     443,
        Protocol: "tcp",
    }},
})
if err != nil {
    log.Fatal(err)
}
```

## Append allow or deny rules

Use `client.Config().Update` with `AddAllowRules` or `AddDenyRules` to append request matchers to an existing base-policy endpoint. Both operations require an `L7RuleTarget` naming the rule, host, every affected port, and every binary governed by that rule. The gateway rejects missing scope or a scope that differs from the current policy without applying the merge batch.

```go
result, err := client.Config().Update(ctx, "default", &v1.ConfigUpdate{
    Name: "my-sandbox",
    MergeOperations: []v1.PolicyMergeOperation{{
        AddAllowRules: &v1.AddAllowRules{
            Target: &v1.L7RuleTarget{
                RuleName: "api",
                Host: "api.example.com",
                Ports: []uint32{443, 8443},
                Binaries: []v1.PolicyNetworkBinary{
                    {Path: "/usr/bin/curl"},
                    {Path: "/usr/bin/wget"},
                },
            },
            Rules: []v1.L7Rule{{
                Allow: &v1.L7Allow{Method: "POST", Path: "/admin"},
            }},
        },
    }},
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Policy version: %d\n", result.Version)
```

This example explicitly permits both binaries to make the new request on both ports. For a rule that permits any binary, set `AnyBinary: true` and omit `Binaries`. Omitting both fields is invalid; the SDK never infers any-binary permission.

`Target.Path` selects the existing endpoint path and is separate from the appended request matcher's path. Leave it `nil` when the rule, host, and ports identify a unique endpoint. To choose an endpoint with a specific path, pass a pointer to that path; a pointer to an empty string selects an endpoint without a path selector. Use `AddDenyRules` with the same target shape and a `DenyRules` payload to append deny matchers.

See also: [Error Handling](../error-handling.md), [Testing](../testing.md)
