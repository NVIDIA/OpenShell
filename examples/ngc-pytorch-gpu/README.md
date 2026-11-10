# NGC PyTorch GPU Sandbox

Run an NGC PyTorch image from `nvcr.io` in a GPU sandbox and check that CUDA
works from Python.

NGC images keep libraries outside the paths that the
[default policy](../../docs/how-it-works/policies/default-policy.mdx) grants,
so `import torch` fails in a default sandbox. `policy.yaml` adds those paths.

Run these commands from `examples/ngc-pytorch-gpu`. You need a gateway whose
compute driver can attach a GPU (Docker or Podman with the NVIDIA Container
Toolkit and CDI, Kubernetes with the NVIDIA device plugin, or the MicroVM
driver with one GPU passed through), and the `openshell` CLI on the host.

## 1. Run the check

```shell
openshell sandbox create \
  --name torch-check \
  --gpu \
  --from nvcr.io/nvidia/pytorch:25.09-py3 \
  --policy policy.yaml \
  --no-keep --no-tty \
  -- python -c 'import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.device_count()); x = torch.ones(1024, device="cuda"); print("sum", (x * 2).sum().item())'
```

The first run pulls the image, which is several gigabytes. A working sandbox
prints the PyTorch version, `True`, the GPU count, and `sum 2048.0`.
`--no-keep` deletes the sandbox when the command exits.

To use the policy for every sandbox you create, point
`OPENSHELL_SANDBOX_POLICY` at it instead of passing `--policy`:

```shell
export OPENSHELL_SANDBOX_POLICY="$PWD/policy.yaml"
```

## 2. What fails without the policy

Run the same command without `--policy` and the import fails:

```text
OSError: libmpi.so.40: cannot open shared object file: No such file or directory
```

The library exists. NGC images ship HPC-X under `/opt/hpcx`, and the loader
cache points `libmpi.so.40` there. Landlock refuses the `open()` with `EACCES`,
and glibc reports every refused candidate as "No such file or directory".
`ls -l` and `ldconfig -p` still list the file because Landlock does not govern
`stat()`, so neither command reveals the denial. To confirm a suspected path,
grant it in a copy of the policy and run the command again.

`policy.yaml` makes these additions to the default policy:

| Path | Access | Needed by |
|---|---|---|
| `/opt` | Read-only | HPC-X, UCX, and other NGC libraries that PyTorch loads at import. |
| `/sys` | Read-only | PyTorch's cpuinfo (`/sys/devices/system/cpu`); NCCL, NVML, and hwloc topology discovery (`/sys/bus/pci`, `/sys/class`, `/sys/devices/system/node`). |
| `/dev/shm` | Read-write | PyTorch DataLoader workers and NCCL's shared-memory transport. |

Without `/sys`, every PyTorch run starts with
`Error in cpuinfo: failed to parse the list of possible processors in /sys/devices/system/cpu/possible`.
The policy grants the whole tree because multi-GPU NCCL reads well beyond
that one directory.

`/proc` stays read-only. CUDA writes thread names during initialization,
and the runtime brokers those writes without general `/proc` write access.
OpenShell adds the GPU device nodes at runtime when the sandbox requests a GPU,
so the policy does not list them.

The policy defines no network rules, so the sandbox has no outbound access.
Add network rules if your workload downloads models or datasets.
