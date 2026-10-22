// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checked conversion between the public protobuf contract and local Rust handles.
//!
//! All required message presence, enums, numeric ranges, paths, and identities
//! are validated here before entering the existing admission/lifecycle code.

use crate::{
    boundary_protocol::{self as w, FrameError},
    proto as p,
};
use openshell_isolation_interface::contract as c;
use prost::Message;
use std::path::{Path, PathBuf};

pub trait WireMessage: Sized {
    type Proto;
    fn to_proto(&self) -> Result<Self::Proto, FrameError>;
    fn from_proto(value: Self::Proto) -> Result<Self, FrameError>;
}
fn invalid(message: impl ToString) -> FrameError {
    FrameError::Protobuf(message.to_string())
}
fn required<T>(value: Option<T>) -> Result<T, FrameError> {
    value.ok_or_else(|| invalid("required message or variant missing"))
}
fn path(value: &Path) -> Result<String, FrameError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("path is not UTF-8"))
}
fn parse<T: std::str::FromStr>(value: &str) -> Result<T, FrameError>
where
    T::Err: std::fmt::Display,
{
    value.parse().map_err(invalid)
}
fn number<T: TryFrom<u64>>(value: u64) -> Result<T, FrameError> {
    value
        .try_into()
        .map_err(|_| invalid("integer out of range"))
}

macro_rules! enumeration {
    ($rust:ty, $proto:ty, {$($variant:ident),+ $(,)?}) => {
        impl WireMessage for $rust {
            type Proto = $proto;
            fn to_proto(&self) -> Result<Self::Proto, FrameError> {
                Ok(match self { $(Self::$variant => <$proto>::$variant),+ })
            }
            fn from_proto(value: Self::Proto) -> Result<Self, FrameError> {
                match value { $(<$proto>::$variant => Ok(Self::$variant)),+, _ => Err(invalid("unspecified enum")) }
            }
        }
    };
}
enumeration!(w::SignalWire, p::BoundarySignal, {Term, Kill, Int, Hup});
enumeration!(w::NetworkModeWire, p::NetworkMode, {Block, Proxy, Allow});
enumeration!(w::LandlockCompatibilityWire, p::LandlockCompatibility, {BestEffort, HardRequirement});
enumeration!(w::RuntimeHelperWire, p::RuntimeHelper, { Sftp });
enumeration!(w::ProcessKindWire, p::ProcessKind, {Main, Exec});
enumeration!(w::BoundaryErrorKind, p::BoundaryErrorKind, {Invalid, Denied, Unavailable, Terminated, Process, Unsupported});
enumeration!(c::TcpOpenDenial, p::TcpOpenDenial, {PolicyDenied, IdentityUnavailable, InvalidDestination, ResourceExhausted, MediationUnavailable});
enumeration!(c::DnsTransport, p::DnsTransport, {Udp, Tcp});
fn enum_value<E: TryFrom<i32>>(value: i32) -> Result<E, FrameError> {
    value.try_into().map_err(|_| invalid("unknown enum"))
}

impl WireMessage for w::ExitStatusWire {
    type Proto = p::ExitStatus;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::exit_status::Status;
        Ok(p::ExitStatus {
            status: Some(match self {
                Self::Exited(v) => Status::Exited(*v),
                Self::Signaled(v) => Status::Signaled(*v),
            }),
        })
    }
    fn from_proto(value: Self::Proto) -> Result<Self, FrameError> {
        use p::exit_status::Status;
        Ok(match required(value.status)? {
            Status::Exited(v) => Self::Exited(v),
            Status::Signaled(v) => Self::Signaled(v),
        })
    }
}
impl WireMessage for w::SandboxPolicyWire {
    type Proto = p::SandboxPolicy;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::SandboxPolicy {
            version: self.version,
            read_only: self
                .read_only
                .iter()
                .map(|v| path(v))
                .collect::<Result<_, _>>()?,
            read_write: self
                .read_write
                .iter()
                .map(|v| path(v))
                .collect::<Result<_, _>>()?,
            include_workdir: self.include_workdir,
            network: self.network.to_proto()? as i32,
            proxy_addr: self.proxy_addr.map(|v| v.to_string()),
            landlock: self.landlock.to_proto()? as i32,
            run_as_user: self.run_as_user.clone(),
            run_as_group: self.run_as_group.clone(),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            version: v.version,
            read_only: v.read_only.into_iter().map(PathBuf::from).collect(),
            read_write: v.read_write.into_iter().map(PathBuf::from).collect(),
            include_workdir: v.include_workdir,
            network: w::NetworkModeWire::from_proto(enum_value(v.network)?)?,
            proxy_addr: v.proxy_addr.map(|v| parse(&v)).transpose()?,
            landlock: w::LandlockCompatibilityWire::from_proto(enum_value(v.landlock)?)?,
            run_as_user: v.run_as_user,
            run_as_group: v.run_as_group,
        })
    }
}
fn duration(micros: u64) -> Result<prost_types::Duration, FrameError> {
    let seconds = number(micros / 1_000_000)?;
    if seconds > 315_576_000_000 {
        return Err(invalid("duration outside protobuf range"));
    }
    Ok(prost_types::Duration {
        seconds,
        nanos: number((micros % 1_000_000) * 1000)?,
    })
}
fn micros(v: Option<prost_types::Duration>) -> Result<u64, FrameError> {
    let v = v.unwrap_or_default();
    if !(0..=315_576_000_000).contains(&v.seconds)
        || !(0..1_000_000_000).contains(&v.nanos)
        || v.nanos % 1000 != 0
    {
        return Err(invalid("invalid microsecond duration"));
    }
    u64::try_from(v.seconds)
        .map_err(invalid)?
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(u64::try_from(v.nanos).ok()? / 1000))
        .ok_or_else(|| invalid("duration overflow"))
}
impl WireMessage for w::AgentSpecWire {
    type Proto = p::AgentSpec;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::AgentSpec {
            program: self.program.clone(),
            args: self.args.clone(),
            workdir: self.workdir.clone(),
            timeout: Some(prost_types::Duration {
                seconds: if self.timeout_secs <= 315_576_000_000 {
                    number(self.timeout_secs)?
                } else {
                    return Err(invalid("timeout outside protobuf duration range"));
                },
                nanos: 0,
            }),
            interactive: self.interactive,
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        let timeout = v.timeout.unwrap_or_default();
        if !(0..=315_576_000_000).contains(&timeout.seconds) || timeout.nanos != 0 {
            return Err(invalid("timeout must be whole nonnegative seconds"));
        }
        Ok(Self {
            program: v.program,
            args: v.args,
            workdir: v.workdir,
            timeout_secs: u64::try_from(timeout.seconds).map_err(invalid)?,
            interactive: v.interactive,
        })
    }
}
impl WireMessage for w::ExecSpecWire {
    type Proto = p::ExecSpec;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::ExecSpec {
            program: self.program.clone(),
            args: self.args.clone(),
            shell: self.shell.as_ref().map(|s| p::ShellSpec {
                command: s.command.clone(),
                login: s.login,
            }),
            runtime_helper: self
                .runtime_helper
                .as_ref()
                .map(WireMessage::to_proto)
                .transpose()?
                .map(|v| v as i32),
            env: self
                .env
                .iter()
                .map(|(name, value)| p::EnvironmentEntry {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            workdir: self.workdir.clone(),
            pty: self.pty,
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            program: v.program,
            args: v.args,
            shell: v.shell.map(|s| w::ShellSpecWire {
                command: s.command,
                login: s.login,
            }),
            runtime_helper: v
                .runtime_helper
                .map(|v| w::RuntimeHelperWire::from_proto(enum_value(v)?))
                .transpose()?,
            env: v.env.into_iter().map(|v| (v.name, v.value)).collect(),
            workdir: v.workdir,
            pty: v.pty,
        })
    }
}
impl WireMessage for w::ExecutableIdentityWire {
    type Proto = p::ExecutableIdentity;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::ExecutableIdentity {
            path: path(&self.path)?,
            digest: self.digest.as_ref().map(ToString::to_string),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            path: v.path.into(),
            digest: v.digest.map(|v| parse(&v)).transpose()?,
        })
    }
}
impl WireMessage for w::BinaryIdentityWire {
    type Proto = p::BinaryIdentity;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::binary_identity::Result as R;
        Ok(p::BinaryIdentity {
            result: Some(match self {
                Self::Resolved {
                    executable,
                    ancestors,
                    cmdline_paths,
                } => R::Resolved(p::ResolvedBinaryIdentity {
                    executable: Some(executable.to_proto()?),
                    ancestors: ancestors
                        .iter()
                        .map(WireMessage::to_proto)
                        .collect::<Result<_, _>>()?,
                    cmdline_paths: cmdline_paths
                        .iter()
                        .map(|v| path(v))
                        .collect::<Result<_, _>>()?,
                }),
                Self::Failed { message } => R::Failed(message.clone()),
            }),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        use p::binary_identity::Result as R;
        Ok(match required(v.result)? {
            R::Resolved(v) => Self::Resolved {
                executable: w::ExecutableIdentityWire::from_proto(required(v.executable)?)?,
                ancestors: v
                    .ancestors
                    .into_iter()
                    .map(w::ExecutableIdentityWire::from_proto)
                    .collect::<Result<_, _>>()?,
                cmdline_paths: v.cmdline_paths.into_iter().map(PathBuf::from).collect(),
            },
            R::Failed(message) => Self::Failed { message },
        })
    }
}
impl WireMessage for w::MediationTimingWire {
    type Proto = p::MediationTiming;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::MediationTiming {
            notification_to_queue: Some(duration(self.notification_to_queue_us)?),
            queue_wait: Some(duration(self.queue_wait_us)?),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            notification_to_queue_us: micros(v.notification_to_queue)?,
            queue_wait_us: micros(v.queue_wait)?,
        })
    }
}
impl WireMessage for c::TcpOpenDecision {
    type Proto = p::TcpOpenDecision;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::tcp_open_decision::Decision;
        Ok(p::TcpOpenDecision {
            decision: Some(match self {
                Self::Denied(v) => Decision::Denied(v.to_proto()? as i32),
                Self::RelayReady => Decision::RelayReady(p::RelayReady {}),
            }),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        use p::tcp_open_decision::Decision;
        Ok(match required(v.decision)? {
            Decision::Denied(v) => Self::Denied(c::TcpOpenDenial::from_proto(enum_value(v)?)?),
            Decision::RelayReady(_) => Self::RelayReady,
        })
    }
}
impl WireMessage for c::BoundaryConfirmation {
    type Proto = p::BoundaryConfirmation;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::BoundaryConfirmation {
            generation: self.generation.clone(),
            identity: Some(p::ResolvedWorkloadIdentity {
                uid: self.identity.uid,
                gid: self.identity.gid,
                supplementary_gids: self.identity.supplementary_gids.clone(),
                source: self.identity.source.clone(),
                resource_digest: self.identity.resource_digest.clone(),
            }),
            session_id: self.session_id.to_string(),
            resource_claims: self.resource_claims.clone(),
            provisioning_evidence_digest: self.provisioning_evidence_digest.to_string(),
            backend_audit: if self.backend_audit.is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&self.backend_audit).map_err(invalid)?
            },
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        let identity = required(v.identity)?;
        Ok(Self {
            generation: v.generation,
            identity: c::ResolvedWorkloadIdentity::new(
                identity.uid,
                identity.gid,
                identity.supplementary_gids,
                identity.source,
                identity.resource_digest,
            )
            .map_err(invalid)?,
            session_id: parse(&v.session_id)?,
            resource_claims: v.resource_claims,
            provisioning_evidence_digest: parse(&v.provisioning_evidence_digest)?,
            backend_audit: if v.backend_audit.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_slice(&v.backend_audit).map_err(|error| {
                    invalid(format!("backend_audit must be UTF-8 JSON: {error}"))
                })?
            },
        })
    }
}
impl WireMessage for w::SessionSnapshotWire {
    type Proto = p::SessionSnapshot;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::SessionSnapshot {
            generation: self.generation.clone(),
            processes: self
                .processes
                .iter()
                .map(|v| {
                    Ok(p::ProcessSnapshot {
                        process_id: v.process_id.clone(),
                        kind: v.kind.to_proto()? as i32,
                        terminal: v.terminal,
                        status: v.status.as_ref().map(WireMessage::to_proto).transpose()?,
                        retained_output: Some(p::OutputWindow {
                            first_sequence: v.retained_output.first_sequence,
                            next_sequence: v.retained_output.next_sequence,
                            truncated: v.retained_output.truncated,
                        }),
                    })
                })
                .collect::<Result<_, FrameError>>()?,
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            generation: v.generation,
            processes: v
                .processes
                .into_iter()
                .map(|v| {
                    let output = required(v.retained_output)?;
                    Ok(w::ProcessSnapshotWire {
                        process_id: v.process_id,
                        kind: w::ProcessKindWire::from_proto(enum_value(v.kind)?)?,
                        terminal: v.terminal,
                        status: v.status.map(w::ExitStatusWire::from_proto).transpose()?,
                        retained_output: w::OutputWindowWire {
                            first_sequence: output.first_sequence,
                            next_sequence: output.next_sequence,
                            truncated: output.truncated,
                        },
                    })
                })
                .collect::<Result<_, FrameError>>()?,
        })
    }
}
fn timestamp(v: u64) -> Result<prost_types::Timestamp, FrameError> {
    let seconds = number(v / 1000)?;
    if seconds > 253_402_300_799 {
        return Err(invalid("timestamp outside protobuf range"));
    }
    Ok(prost_types::Timestamp {
        seconds,
        nanos: number((v % 1000) * 1_000_000)?,
    })
}
fn millis(v: prost_types::Timestamp) -> Result<u64, FrameError> {
    if !(0..=253_402_300_799).contains(&v.seconds)
        || !(0..1_000_000_000).contains(&v.nanos)
        || v.nanos % 1_000_000 != 0
    {
        return Err(invalid("invalid millisecond timestamp"));
    }
    Ok(u64::try_from(v.seconds).map_err(invalid)? * 1000
        + u64::try_from(v.nanos).map_err(invalid)? / 1_000_000)
}
impl WireMessage for w::RequestEnvelope {
    type Proto = p::RequestEnvelope;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::request_envelope::Request as P;
        use w::Request as W;
        let request = match &self.request {
            W::DiscoverPolicy => P::DiscoverPolicy(p::DiscoverPolicy {}),
            W::Attach {
                supervisor_instance_id,
                policy,
            } => P::Attach(p::Attach {
                supervisor_instance_id: supervisor_instance_id.to_string(),
                policy: Some(policy.to_proto()?),
            }),
            W::Confirm => P::Confirm(p::Confirm {}),
            W::StartAgent {
                sandbox_id,
                spec,
                ca_cert,
                ca_bundle,
                provider_env_revision,
                provider_env,
                provider_files,
            } => P::StartAgent(p::StartAgent {
                sandbox_id: sandbox_id.clone(),
                spec: Some(spec.to_proto()?),
                ca_cert: ca_cert.clone(),
                ca_bundle: ca_bundle.clone(),
                provider_env_revision: *provider_env_revision,
                provider_env: provider_env.clone().into_iter().collect(),
                provider_files: provider_files.clone().into_iter().collect(),
            }),
            W::UpdateProviderEnvironment {
                generation,
                revision,
                provider_env,
                provider_files,
            } => P::UpdateProviderEnvironment(p::UpdateProviderEnvironment {
                generation: *generation,
                revision: *revision,
                provider_env: provider_env.clone().into_iter().collect(),
                provider_files: provider_files.clone().into_iter().collect(),
            }),
            W::AttachProcess { process_id } => P::AttachProcess(p::AttachProcess {
                process_id: process_id.clone(),
            }),
            W::Wait { process_id } => P::Wait(p::Wait {
                process_id: process_id.clone(),
            }),
            W::Signal { process_id, signal } => P::Signal(p::Signal {
                process_id: process_id.clone(),
                signal: signal.to_proto()? as i32,
            }),
            W::Terminate { process_id } => P::Terminate(p::Terminate {
                process_id: process_id.clone(),
            }),
            W::TerminateBoundary => P::TerminateBoundary(p::TerminateBoundary {}),
            W::Exec { spec } => P::Exec(p::Exec {
                spec: Some(spec.to_proto()?),
                exec_admission_deadline: Some(timestamp(
                    self.exec_admission_deadline_unix_ms
                        .ok_or_else(|| invalid("exec admission deadline missing"))?,
                )?),
            }),
            W::Resize {
                process_id,
                cols,
                rows,
            } => P::Resize(p::Resize {
                process_id: process_id.clone(),
                cols: u32::from(*cols),
                rows: u32::from(*rows),
            }),
            W::LoopbackConnect { host, port } => P::LoopbackConnect(p::LoopbackConnect {
                host: host.to_string(),
                port: u32::from(*port),
            }),
            W::OpenMediation => P::OpenMediation(p::OpenMediation {}),
            W::AcceptNetwork => P::AcceptNetwork(p::AcceptNetwork {}),
        };
        Ok(p::RequestEnvelope {
            request_id: self.request_id.clone(),
            request: Some(request),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        use p::request_envelope::Request as P;
        use w::Request as W;
        let mut expires = None;
        let request = match required(v.request)? {
            P::DiscoverPolicy(_) => W::DiscoverPolicy,
            P::Attach(v) => W::Attach {
                supervisor_instance_id: parse(&v.supervisor_instance_id)?,
                policy: Box::new(w::SandboxPolicyWire::from_proto(required(v.policy)?)?),
            },
            P::Confirm(_) => W::Confirm,
            P::StartAgent(v) => W::StartAgent {
                sandbox_id: v.sandbox_id,
                spec: w::AgentSpecWire::from_proto(required(v.spec)?)?,
                ca_cert: v.ca_cert,
                ca_bundle: v.ca_bundle,
                provider_env_revision: v.provider_env_revision,
                provider_env: v.provider_env.into_iter().collect(),
                provider_files: v.provider_files.into_iter().collect(),
            },
            P::UpdateProviderEnvironment(v) => W::UpdateProviderEnvironment {
                generation: v.generation,
                revision: v.revision,
                provider_env: v.provider_env.into_iter().collect(),
                provider_files: v.provider_files.into_iter().collect(),
            },
            P::AttachProcess(v) => W::AttachProcess {
                process_id: v.process_id,
            },
            P::Wait(v) => W::Wait {
                process_id: v.process_id,
            },
            P::Signal(v) => W::Signal {
                process_id: v.process_id,
                signal: w::SignalWire::from_proto(enum_value(v.signal)?)?,
            },
            P::Terminate(v) => W::Terminate {
                process_id: v.process_id,
            },
            P::TerminateBoundary(_) => W::TerminateBoundary,
            P::Exec(v) => {
                expires = Some(millis(required(v.exec_admission_deadline)?)?);
                W::Exec {
                    spec: w::ExecSpecWire::from_proto(required(v.spec)?)?,
                }
            }
            P::Resize(v) => W::Resize {
                process_id: v.process_id,
                cols: number(v.cols.into())?,
                rows: number(v.rows.into())?,
            },
            P::LoopbackConnect(v) => W::LoopbackConnect {
                host: parse(&v.host)?,
                port: number(v.port.into())?,
            },
            P::OpenMediation(_) => W::OpenMediation,
            P::AcceptNetwork(_) => W::AcceptNetwork,
        };
        // The server derives a fingerprint from decoded typed fields. Clients
        // supply only the random ID; protobuf map order never changes a replay.
        parse::<uuid::Uuid>(&v.request_id)?;
        let mut envelope = Self {
            request_id: v.request_id,
            payload_digest: String::new(),
            exec_admission_deadline_unix_ms: expires,
            request,
        };
        envelope.payload_digest = w::request_envelope_digest(&envelope.request, expires)?;
        Ok(envelope)
    }
}
impl WireMessage for w::ResponseEnvelope {
    type Proto = p::ResponseEnvelope;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::response_envelope::Response as P;
        use w::Response as W;
        let response = match &self.response {
            W::ImagePolicy { yaml, invalid } => P::ImagePolicy(p::ImagePolicy {
                yaml: yaml.clone(),
                invalid: *invalid,
            }),
            W::Attached { snapshot } => P::Attached(p::Attached {
                snapshot: Some(snapshot.to_proto()?),
            }),
            W::Confirmed { confirmation } => P::Confirmed(p::Confirmed {
                confirmation: Some(confirmation.to_proto()?),
            }),
            W::Started {
                process_id,
                provider_env_revision,
                provider_env_generation,
            } => P::Started(p::Started {
                process_id: process_id.clone(),
                provider_env_revision: *provider_env_revision,
                provider_env_generation: *provider_env_generation,
            }),
            W::ProviderEnvironmentUpdated {
                revision,
                generation,
                applied,
            } => P::ProviderEnvironmentUpdated(p::ProviderEnvironmentUpdated {
                revision: *revision,
                generation: *generation,
                applied: *applied,
            }),
            W::ProcessAttached { terminal } => P::ProcessAttached(p::ProcessAttached {
                terminal: *terminal,
            }),
            W::Exited { status } => P::Exited(p::Exited {
                status: Some(status.to_proto()?),
            }),
            W::Signaled => P::Signaled(p::Signaled {}),
            W::Terminated => P::Terminated(p::Terminated {}),
            W::BoundaryTerminated => P::BoundaryTerminated(p::BoundaryTerminated {}),
            W::ExecStarted { process_id, pty } => P::ExecStarted(p::ExecStarted {
                process_id: process_id.clone(),
                pty: *pty,
            }),
            W::Resized => P::Resized(p::Resized {}),
            W::LoopbackConnected => P::LoopbackConnected(p::LoopbackConnected {}),
            W::MediationReady => P::MediationReady(p::MediationReady {}),
            W::NetworkConnected {
                identity,
                destination,
                socket,
                policy_generation,
                timing,
            } => P::NetworkConnected(p::NetworkConnected {
                identity: Some(identity.to_proto()?),
                destination: destination.to_string(),
                socket: socket.as_ref().map(|v| p::NetworkSocketMetadata {
                    socket_cookie: v.socket_cookie,
                    nonblocking: v.nonblocking,
                    process_generation: v.process_generation,
                }),
                policy_generation: *policy_generation,
                timing: Some(timing.to_proto()?),
            }),
            W::Error { kind, message } => P::Error(p::Error {
                kind: kind.to_proto()? as i32,
                message: message.clone(),
            }),
        };
        Ok(p::ResponseEnvelope {
            request_id: self.request_id.clone(),
            response: Some(response),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        use p::response_envelope::Response as P;
        use w::Response as W;
        let response = match required(v.response)? {
            P::ImagePolicy(v) => W::ImagePolicy {
                yaml: v.yaml,
                invalid: v.invalid,
            },
            P::Attached(v) => W::Attached {
                snapshot: w::SessionSnapshotWire::from_proto(required(v.snapshot)?)?,
            },
            P::Confirmed(v) => W::Confirmed {
                confirmation: Box::new(c::BoundaryConfirmation::from_proto(required(
                    v.confirmation,
                )?)?),
            },
            P::Started(v) => W::Started {
                process_id: v.process_id,
                provider_env_revision: v.provider_env_revision,
                provider_env_generation: v.provider_env_generation,
            },
            P::ProviderEnvironmentUpdated(v) => W::ProviderEnvironmentUpdated {
                revision: v.revision,
                generation: v.generation,
                applied: v.applied,
            },
            P::ProcessAttached(v) => W::ProcessAttached {
                terminal: v.terminal,
            },
            P::Exited(v) => W::Exited {
                status: w::ExitStatusWire::from_proto(required(v.status)?)?,
            },
            P::Signaled(_) => W::Signaled,
            P::Terminated(_) => W::Terminated,
            P::BoundaryTerminated(_) => W::BoundaryTerminated,
            P::ExecStarted(v) => W::ExecStarted {
                process_id: v.process_id,
                pty: v.pty,
            },
            P::Resized(_) => W::Resized,
            P::LoopbackConnected(_) => W::LoopbackConnected,
            P::MediationReady(_) => W::MediationReady,
            P::NetworkConnected(v) => W::NetworkConnected {
                identity: w::BinaryIdentityWire::from_proto(required(v.identity)?)?,
                destination: parse(&v.destination)?,
                socket: v.socket.map(|v| c::NetworkSocketMetadata {
                    socket_cookie: v.socket_cookie,
                    nonblocking: v.nonblocking,
                    process_generation: v.process_generation,
                }),
                policy_generation: v.policy_generation,
                timing: w::MediationTimingWire::from_proto(v.timing.unwrap_or_default())?,
            },
            P::Error(v) => W::Error {
                kind: w::BoundaryErrorKind::from_proto(enum_value(v.kind)?)?,
                message: v.message,
            },
        };
        Ok(Self {
            request_id: v.request_id,
            response,
        })
    }
}
impl WireMessage for crate::mediation::DnsQueryWire {
    type Proto = p::DnsQuery;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        Ok(p::DnsQuery {
            stream_id: 0,
            request: self.request.clone(),
            transport: self.transport.to_proto()? as i32,
            identity: Some(self.identity.to_proto()?),
            timing: Some(self.timing.to_proto()?),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        Ok(Self {
            request: v.request,
            transport: c::DnsTransport::from_proto(enum_value(v.transport)?)?,
            identity: w::BinaryIdentityWire::from_proto(required(v.identity)?)?,
            timing: w::MediationTimingWire::from_proto(v.timing.unwrap_or_default())?,
        })
    }
}
impl WireMessage for w::DnsQueryResultWire {
    type Proto = p::DnsResponse;
    fn to_proto(&self) -> Result<Self::Proto, FrameError> {
        use p::dns_response::Result as R;
        Ok(p::DnsResponse {
            stream_id: 0,
            result: Some(match self {
                Self::Response(v) => R::Response(v.clone()),
                Self::Error(v) => R::Error(v.clone()),
            }),
        })
    }
    fn from_proto(v: Self::Proto) -> Result<Self, FrameError> {
        use p::dns_response::Result as R;
        Ok(match required(v.result)? {
            R::Response(v) => Self::Response(v),
            R::Error(v) => Self::Error(v),
        })
    }
}

pub fn encode<T: WireMessage>(value: &T) -> Result<Vec<u8>, FrameError>
where
    T::Proto: Message,
{
    Ok(value.to_proto()?.encode_to_vec())
}
pub fn decode<T: WireMessage>(bytes: &[u8]) -> Result<T, FrameError>
where
    T::Proto: Message + Default,
{
    T::from_proto(T::Proto::decode(bytes).map_err(invalid)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_validation_rejects_missing_context_and_unknown_signal() {
        let id = uuid::Uuid::new_v4().to_string();
        let attach = p::RequestEnvelope {
            request_id: id.clone(),
            request: Some(p::request_envelope::Request::Attach(p::Attach {
                supervisor_instance_id: uuid::Uuid::new_v4().to_string(),
                policy: None,
            })),
        };
        assert!(w::RequestEnvelope::from_proto(attach).is_err());
        let signal = p::RequestEnvelope {
            request_id: id,
            request: Some(p::request_envelope::Request::Signal(p::Signal {
                process_id: "main".into(),
                signal: 99,
            })),
        };
        assert!(w::RequestEnvelope::from_proto(signal).is_err());
    }

    #[test]
    fn exec_requires_the_original_valid_deadline() {
        let request = w::RequestEnvelope::new(w::Request::Exec {
            spec: w::ExecSpecWire {
                program: "/bin/true".into(),
                args: vec![],
                shell: None,
                runtime_helper: None,
                env: vec![],
                workdir: None,
                pty: false,
            },
        })
        .unwrap();
        let mut value = request.to_proto().unwrap();
        let Some(p::request_envelope::Request::Exec(exec)) = value.request.as_mut() else {
            unreachable!()
        };
        exec.exec_admission_deadline = None;
        assert!(w::RequestEnvelope::from_proto(value).is_err());
        let mut value = request.to_proto().unwrap();
        let Some(p::request_envelope::Request::Exec(exec)) = value.request.as_mut() else {
            unreachable!()
        };
        exec.exec_admission_deadline.as_mut().unwrap().nanos = -1;
        assert!(w::RequestEnvelope::from_proto(value).is_err());
        let mut value = request.to_proto().unwrap();
        let Some(p::request_envelope::Request::Exec(exec)) = value.request.as_mut() else {
            unreachable!()
        };
        exec.exec_admission_deadline.as_mut().unwrap().seconds += 1;
        let changed = w::RequestEnvelope::from_proto(value).unwrap();
        assert_eq!(changed.request_id, request.request_id);
        assert_ne!(changed.payload_digest, request.payload_digest);
    }

    #[test]
    fn resize_rejects_values_outside_the_rust_contract() {
        let value = p::RequestEnvelope {
            request_id: uuid::Uuid::new_v4().to_string(),
            request: Some(p::request_envelope::Request::Resize(p::Resize {
                process_id: "main".into(),
                cols: 65_536,
                rows: 24,
            })),
        };
        assert!(w::RequestEnvelope::from_proto(value).is_err());
    }

    #[test]
    fn publication_retains_large_counters_without_a_client_digest() {
        let request = w::RequestEnvelope::new(w::Request::UpdateProviderEnvironment {
            generation: 9_007_199_254_740_993,
            revision: u64::MAX,
            provider_env: std::collections::HashMap::from([("KEY".into(), "value".into())]),
            provider_files: std::collections::HashMap::default(),
        })
        .unwrap();
        let bytes = encode(&request).unwrap();
        let decoded: w::RequestEnvelope = decode(&bytes).unwrap();
        assert_eq!(decoded, request);
    }
}
