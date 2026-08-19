# Sandbox Templates

Accessor: `client.SandboxTemplates()`

Manage reusable workspace-scoped sandbox templates. Templates carry driver-specific configuration such as runtime isolation, mounts, and startup behavior. Create sandboxes from templates with `client.Sandboxes().CreateFromTemplate(...)`.

## Create

```go
template, err := client.SandboxTemplates().Create(ctx, "default", &v1.SandboxTemplate{
    Name: "gpu-kata",
    Spec: v1.SandboxTemplateSpec{
        Workload: &v1.SandboxWorkloadConfig{Image: "python:3.12"},
        DriverConfig: map[string]any{
            "kubernetes": map[string]any{
                "runtime_class_name": "kata",
            },
        },
    },
})
```

## Get

```go
template, err := client.SandboxTemplates().Get(ctx, "default", "gpu-kata")
fmt.Println(template.Spec.Workload.Image)
```

## List

```go
templates, err := client.SandboxTemplates().List(ctx, "default")

templates, err = client.SandboxTemplates().List(ctx, "default", v1.ListOptions{
    Limit: 50,
})
```

Platform administrators can list across workspaces:

```go
templates, err := client.SandboxTemplates().List(ctx, "default", v1.ListOptions{
    AllWorkspaces: true,
})
```

## Delete

```go
err := client.SandboxTemplates().Delete(ctx, "default", "gpu-kata")
```

## Create From Template

```go
sandbox, err := client.Sandboxes().CreateFromTemplate(
    ctx,
    "default",
    "gpu-job",
    "gpu-kata",
    nil,
    []string{"openai"},
    nil,
)
```
