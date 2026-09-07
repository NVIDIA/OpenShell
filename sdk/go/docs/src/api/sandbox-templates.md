# Sandbox Templates

Accessor: `client.SandboxTemplates()`

Manage reusable, workspace-scoped sandbox workload templates. Templates own the
portable workload shape and optional driver-specific config. Sandbox creation
can reference a template by name while supplying only governance fields such as
providers or policy.

The Go SDK names the reusable resource `SandboxWorkloadTemplate` because
`SandboxTemplate` already represents the legacy inline compute template inside
`SandboxSpec`.

## Create

Creates a reusable template in a workspace.

```go
gpuCount := uint32(1)

template, err := client.SandboxTemplates().Create(ctx, "default", &v1.SandboxWorkloadTemplate{
    Name: "gpu-kata",
    Labels: map[string]string{
        "team": "platform",
    },
    Spec: v1.SandboxWorkloadTemplateSpec{
        Workload: &v1.SandboxWorkloadConfig{
            Image: "nvcr.io/nvidia/openshell:latest",
            Environment: map[string]string{
                "NVIDIA_VISIBLE_DEVICES": "all",
            },
            Resources: &v1.SandboxResources{
                CPU:    "2",
                Memory: "8Gi",
                GPU:    &v1.SandboxGPURequirements{Count: &gpuCount},
            },
        },
        DriverConfig: map[string]any{
            "kubernetes": map[string]any{
                "pod": map[string]any{
                    "runtime_class_name": "kata",
                },
            },
        },
        DesiredServiceLevel: &v1.SandboxServiceLevel{
            Startup: &v1.SandboxStartup{
                ReadyWithin: 45 * time.Second,
                MaxBurst:    2,
            },
        },
    },
})
```

Set `GPU: &v1.SandboxGPURequirements{}` to request the active driver's default
GPU assignment without specifying a count.

## Create a Sandbox From a Template

Use `CreateSandboxFromTemplate` to create a sandbox from a named reusable
template without changing the legacy `Sandboxes()` interface.

```go
sb, err := client.CreateSandboxFromTemplate(
    ctx,
    "default",
    "training-run",
    "gpu-kata",
    &v1.SandboxSpec{
        Providers: []string{"openai"},
        Policy:    policy,
    },
    map[string]string{"job": "training"},
)
```

When creating from a template, the spec should only include governance fields:
`Providers`, `Policy`, `Command`, and `TTY`. Workload fields such as image,
environment, CPU, memory, GPU, and driver config come from the template.

## Get

Retrieves a template by name.

```go
template, err := client.SandboxTemplates().Get(ctx, "default", "gpu-kata")
fmt.Println(template.Spec.Workload.Image)
```

## List

Lists templates in one workspace or across all workspaces.

```go
templates, err := client.SandboxTemplates().List(ctx, "default", v1.ListOptions{
    Limit:  50,
    Offset: 0,
})

allTemplates, err := client.SandboxTemplates().List(ctx, "", v1.ListOptions{
    AllWorkspaces: true,
})
```

## Delete

Deletes a template by name. Existing sandboxes created from the template are not
deleted.

```go
deleted, err := client.SandboxTemplates().Delete(ctx, "default", "gpu-kata")
```

## Fake Client

The fake client includes the same template sub-client and can be pre-populated
for tests.

```go
client := fake.NewClient()
client.AddSandboxTemplate("default", &types.SandboxWorkloadTemplate{
    Name: "gpu-kata",
    Spec: types.SandboxWorkloadTemplateSpec{
        Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
    },
})
```
