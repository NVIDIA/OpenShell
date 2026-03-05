<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Cluster Issues

Troubleshoot problems with deploying, connecting to, and running NemoClaw clusters.

## Cluster Deploy Fails

**Symptom:** `nemoclaw cluster admin deploy` exits with an error.

**Check:**
1. Is Docker running? The cluster requires Docker to be active.
2. Is the port already in use? Try a different port: `--port 8081`.
3. Does a stale container exist? Destroy and redeploy: `nemoclaw cluster admin destroy && nemoclaw cluster admin deploy`.

## Cluster Not Reachable

**Symptom:** `nemoclaw cluster status` fails to connect.

**Check:**
1. Is the cluster container running? `docker ps | grep nemoclaw`.
2. Was the cluster stopped? Redeploy: `nemoclaw cluster admin deploy`.
3. For remote clusters, is the SSH connection working?

## Health Check Fails During Deploy

**Symptom:** Deploy hangs or times out waiting for health checks.

**Check:**
1. View container logs: `docker logs nemoclaw-cluster`.
2. Check if k3s started: the bootstrap process waits up to 180 attempts (6 minutes) for cluster readiness.
3. Look for resource constraints — k3s needs sufficient memory and disk.
