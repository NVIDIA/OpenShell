<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Managed maximum policies

These examples are gateway-owned ceilings for managed sandboxes. They use the normal sandbox
policy shape plus `metadata` and optional `review` annotations. The maximum does not grant access;
each sandbox still starts with its own narrower policy.

Set a maximum before creating sandboxes:

```shell
openshell policy maximum set --policy examples/managed-maximum-policies/github-rest.yaml --yes
openshell policy maximum get --full
```

Then create a sandbox in the maximum's default mode or select an allowed mode explicitly:

```shell
openshell sandbox create \
  --policy examples/sandbox-policy-quickstart/policy.yaml \
  --permission-mode auto
```

Delete every sandbox before replacing or deleting the maximum:

```shell
openshell policy maximum delete --yes
```

- `github-rest.yaml` makes reads auto-eligible, marks writes for review, and denies deletes.

This first implementation models filesystem paths plus L4 and REST authority. Other protocols and
unsupported endpoint options fail closed with administrator guidance.
