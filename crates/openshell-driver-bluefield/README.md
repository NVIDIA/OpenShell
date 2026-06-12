# openshell-driver-bluefield

`openshell-driver-bluefield` is the BlueField compute driver for OpenShell.
The current backend wraps the VM compute driver with a BlueField lifecycle
extension that claims one host VF per sandbox, binds the VF to `vfio-pci`,
passes it into the QEMU guest, and configures the guest data-plane NIC.

## Operator Contract

Install QEMU and prepare the host once for the current VM backend:

- KVM is available at `/dev/kvm`.
- IOMMU groups are populated.
- `vfio-pci` is loaded.
- The BlueField or ConnectX PF has SR-IOV VFs.
- `qemu-system-x86_64`, `ip`, `nft`, `debugfs`, and `mkfs.ext4` or `mke2fs`
  are on `PATH`.
- A BlueField-capable `vmlinux` is present in the OpenShell `vm-runtime`
  directory, or `OPENSHELL_BLUEFIELD_KERNEL_IMAGE` points to it.

Then run the driver as a normal OpenShell compute driver:

```shell
OPENSHELL_COMPUTE_DRIVER_SOCKET=/run/openshell/bluefield.sock \
OPENSHELL_GRPC_ENDPOINT=http://127.0.0.1:8080 \
openshell-driver-bluefield
```

If the host has more than one usable PF, select one:

```shell
OPENSHELL_BLUEFIELD_HOST_PF=enp177s0f0np0
```

Reserve VFs that are owned by DRA, another service, or manual testing:

```shell
OPENSHELL_BLUEFIELD_RESERVED_VF_INDEXES=0,1,2
```

Do not call `--internal-run-vm` directly for normal operation. The driver
creates root and overlay disks, tap devices, guest IPs, guest MACs, vsock CIDs,
and QEMU passthrough arguments internally.

Docker and Kubernetes BlueField runtimes will have their own prerequisites.
They should not inherit the VM/QEMU guest-kernel requirement.

## Failure Model

At startup the VM backend runs preflight and reports all missing host
prerequisites in one message. Fix the listed host issues and restart the driver.
