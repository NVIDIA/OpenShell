# Data Model: Warm Pool Feasibility Study

## Entities

### MeasurementRun

A single sandbox creation or claim with captured timestamps.

| Field | Type | Description |
|-------|------|-------------|
| run_number | int | Sequential run number within an experiment |
| experiment_id | string | Experiment identifier (e.g., `cold-start`, `warm-pool-default`) |
| config_label | string | Configuration description (e.g., `probe-10s`, `readiness-gate`) |
| create_timestamp | int64 | Nanosecond epoch when kubectl apply was issued |
| ready_timestamp | int64 | Nanosecond epoch when pod/sandbox became Ready |
| delta_ms | float | Latency in milliseconds (ready - create) |
| phases | string | JSON-encoded phase breakdown from events |
| pod_name | string | Name of the pod that was created or claimed |
| status | enum | `success`, `timeout`, `error` |

### ExperimentConfig

A specific combination of settings being tested.

| Field | Type | Description |
|-------|------|-------------|
| experiment_id | string | Unique identifier |
| description | string | Human-readable description |
| readiness_method | enum | `probe-default`, `probe-1s`, `readiness-gate`, `sidecar` |
| pool_size | int | Number of SandboxWarmPool replicas (0 for cold-start) |
| env_injection | bool | Whether SandboxClaim includes env vars |
| target_runs | int | Number of measurement runs to execute |

### PhaseTimestamp

Per-phase latency breakdown extracted from pod events.

| Field | Type | Description |
|-------|------|-------------|
| run_number | int | FK to MeasurementRun |
| phase_name | string | `scheduled`, `image-pulled`, `init-complete`, `supervisor-ready`, `ssh-available` |
| timestamp | int64 | Nanosecond epoch of phase completion |
| delta_from_create_ms | float | Milliseconds from create to this phase |

## Relationships

```
ExperimentConfig 1---* MeasurementRun
MeasurementRun   1---* PhaseTimestamp
```

## State Transitions

### MeasurementRun Lifecycle

```
Created --> Running --> Success
                   \--> Timeout (>60s)
                   \--> Error
```

### Warm Pool Pod Lifecycle

```
Provisioned (warm, NotReady) --> Claimed (SandboxClaim created)
                             --> Ready (readiness condition met)
                             --> Terminated (cleanup)
```

## CSV Output Format

```csv
run,experiment,config,create_ts,ready_ts,delta_ms,pod,status
1,cold-start,openshell-prepulled,1720000000000000000,1720000010500000000,10500.0,sandbox-abc123,success
```
