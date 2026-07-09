# Quickstart: Warm Pool Feasibility Study

## Prerequisites

- AWS credentials for AAET profile
- `rosa` CLI authenticated
- `oc` / `kubectl` CLI
- `gh` CLI for GitHub operations
- `jq` for JSON processing

## Step 1: Provision Cluster

```bash
# Using the rosa Claude Code skill (cc-rosa-rhoai plugin):
# rosa:create warm-pool-study
# Or equivalently via the rosa CLI:
rosa create cluster --cluster-name warm-pool-study --sts --hosted-cp \
  --replicas 3 --compute-machine-type m5.2xlarge --region us-east-2
```

3 worker nodes, m5.2xlarge, us-east-2. Wait for cluster to be Ready (~15 min).

## Step 2: Install Agent Sandbox Operator

```bash
# Check if Red Hat TP is on OperatorHub
oc get packagemanifests -n openshift-marketplace | grep sandbox

# If available, install via Subscription
# If not, apply upstream manifests
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/v0.5.0/manifest.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/v0.5.0/extensions.yaml

# Verify CRDs
kubectl api-resources | grep agents
```

## Step 3: Deploy OpenShell

```bash
# Clone the OpenShell OpenShift deploy repo (pin to a specific commit for reproducibility)
git clone https://github.com/2000krysztof/Openshell-Openshift-Deploy
cd Openshell-Openshift-Deploy
./deploy.sh
openshell status
```

## Step 4: Pre-pull Images

```bash
# DaemonSet that pre-pulls sandbox images on all nodes
kubectl apply -f experiments/manifests/image-prepull-daemonset.yaml
kubectl rollout status ds/image-prepull
```

## Step 5: Run Experiments

```bash
# Cold-start baseline (N=10 pre-pulled, N=5 no pre-pull)
./experiments/measure-cold-start.sh

# Warm pool with default probes
./experiments/measure-warm-pool.sh --config default

# Warm pool with 1s probes
./experiments/measure-warm-pool.sh --config aggressive

# Readiness gates
./experiments/measure-readiness-gates.sh

# Sidecar readiness
./experiments/measure-sidecar-readiness.sh

# Env var injection
./experiments/measure-env-injection.sh
```

## Step 6: Generate RFC

Compile CSV data into the RFC at `rfc/NNNN-warm-pool-feasibility/README.md`.

## Step 7: Tear Down

```bash
# Using the rosa Claude Code skill:
# rosa:delete warm-pool-study
# Or equivalently:
rosa delete cluster --cluster warm-pool-study
```
