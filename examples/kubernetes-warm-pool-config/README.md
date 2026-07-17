# Kubernetes warm-pool templates

Create OpenShell sandbox templates with a startup service level that is below
the Kubernetes driver's configured warm-pool threshold. With the default
threshold of 5 seconds, these examples generate Agent Sandbox `SandboxTemplate`
and `SandboxWarmPool` resources:

```shell
openshell sandbox template create openshell-warm-pool-default \
  --ready-within 1s \
  --max-burst 1

openshell sandbox template create openshell-warm-pool-env-foo \
  --env FOO=bar \
  --ready-within 1s \
  --max-burst 1

openshell sandbox template create openshell-warm-pool-cpu-0-2 \
  --cpu 0.2 \
  --ready-within 1s \
  --max-burst 1
```

Create a sandbox from a warmed template:

```shell
openshell sandbox create --template openshell-warm-pool-env-foo -- echo ready
```
