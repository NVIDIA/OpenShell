// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway request evaluation and interceptor execution.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use json_patch::{PatchOperation, patch};
use metrics::{counter, histogram};
use openshell_core::config::GatewayInterceptorConfig;
use openshell_core::proto::gateway_interceptor::v1::{
    InterceptorEvaluation, InterceptorResult, JsonPatch, ModifyOperationEvaluation,
    PostCommitEvaluation, ValidateEvaluation, interceptor_evaluation,
};
use prost::Message as _;
use prost_types::Struct;
use serde_json::{Map, Value};
use tonic::{Code, Request, Status};
use tracing::{info, warn};

use crate::plan::{BindingPlan, ExecutionPlan, FailurePolicy, Phase, RpcSelector};
use crate::profile_source::GatewayInterceptorProfileSource;
use crate::{InterceptorError, ProtoJsonCodec, Result, routes};

const GRPC_HEADER_LEN: usize = 5;

#[derive(Debug, Clone)]
pub struct GatewayInterceptorRuntime {
    plan: Arc<ExecutionPlan>,
    codec: ProtoJsonCodec,
}

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub principal: BTreeMap<String, String>,
    pub validate_current_state: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct InterceptedRequest {
    pub body: Vec<u8>,
    selector: RpcSelector,
}

#[derive(Debug, Clone, PartialEq)]
struct ValidatedOperation {
    json: Value,
    encoded: Vec<u8>,
}

impl ValidatedOperation {
    fn new(codec: &ProtoJsonCodec, type_name: &str, json: Value) -> Result<Self> {
        let encoded = codec.encode_json_to_message(type_name, &json)?;
        let json = codec.decode_bytes_to_json(type_name, &encoded)?;
        Ok(Self { json, encoded })
    }

    fn apply_patches(
        &self,
        codec: &ProtoJsonCodec,
        type_name: &str,
        patches: &[JsonPatch],
    ) -> Result<Self> {
        let json = apply_json_patches(&self.json, patches).map_err(|err| {
            InterceptorError::InvalidResult(format!(
                "patched operation is not valid {type_name}: {err}"
            ))
        })?;
        Self::new(codec, type_name, json).map_err(|err| {
            InterceptorError::InvalidResult(format!(
                "patched operation is not valid {type_name}: {err}"
            ))
        })
    }
}

impl GatewayInterceptorRuntime {
    pub(crate) async fn build(configs: Vec<GatewayInterceptorConfig>) -> Result<Self> {
        let codec = ProtoJsonCodec::openshell()?;
        let routes = routes::OpenShellRouteIndex::from_descriptor_pool(codec.descriptor_pool())?;
        let plan = ExecutionPlan::load(configs, routes).await?;
        Ok(Self {
            plan: Arc::new(plan),
            codec,
        })
    }

    #[must_use]
    pub fn provider_profile_source(
        &self,
        interceptor_name: &str,
    ) -> Option<GatewayInterceptorProfileSource> {
        self.plan.profile_source(interceptor_name)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plan.is_empty()
    }

    #[must_use]
    pub fn should_intercept_path(&self, path: &str) -> bool {
        let Some(selector) = RpcSelector::from_grpc_path(path) else {
            return false;
        };
        self.plan.should_intercept(&selector)
    }

    pub async fn evaluate_request(
        &self,
        path: &str,
        body: &[u8],
        context: &EvaluationContext,
    ) -> std::result::Result<InterceptedRequest, Status> {
        let selector = RpcSelector::from_grpc_path(path)
            .ok_or_else(|| Status::invalid_argument("invalid gRPC method path"))?;
        let input_type = self
            .plan
            .input_type(&selector)
            .ok_or_else(|| Status::invalid_argument("unknown OpenShell method"))?
            .to_string();
        let frame = GrpcFrame::decode(body)?;
        let operation = self
            .codec
            .decode_bytes_to_json(&input_type, &frame.message)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let mut operation = ValidatedOperation::new(&self.codec, &input_type, operation)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        operation = self
            .evaluate_phase(
                &selector,
                Phase::ModifyOperation,
                &input_type,
                operation,
                context,
            )
            .await?;
        operation = self
            .evaluate_phase(&selector, Phase::Validate, &input_type, operation, context)
            .await?;

        let encoded_operation = self
            .codec
            .decode_bytes_to_json(&input_type, &operation.encoded)
            .map_err(|err| {
                Status::internal(format!(
                    "validated operation encoding became invalid: {err}"
                ))
            })?;
        if encoded_operation != operation.json {
            return Err(Status::internal(
                "validated operation diverged from its encoding before dispatch",
            ));
        }
        let body = GrpcFrame {
            compressed: false,
            message: operation.encoded,
        }
        .encode()
        .map_err(|err| Status::invalid_argument(err.to_string()))?;

        Ok(InterceptedRequest { body, selector })
    }

    pub async fn evaluate_post_commit(
        &self,
        intercepted: &InterceptedRequest,
        response_body: &[u8],
        context: &EvaluationContext,
    ) -> std::result::Result<(), Status> {
        let output_type = self
            .plan
            .output_type(&intercepted.selector)
            .ok_or_else(|| Status::invalid_argument("unknown OpenShell method"))?;
        let frame = GrpcFrame::decode(response_body)?;
        let committed_response = self
            .codec
            .decode_bytes_to_json(output_type, &frame.message)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let committed_response =
            ValidatedOperation::new(&self.codec, output_type, committed_response)
                .map_err(|err| Status::invalid_argument(err.to_string()))?;
        self.evaluate_phase(
            &intercepted.selector,
            Phase::PostCommit,
            output_type,
            committed_response,
            context,
        )
        .await
        .map(|_| ())
    }

    #[must_use]
    pub fn has_post_commit(&self, intercepted: &InterceptedRequest) -> bool {
        self.plan
            .has_binding(&intercepted.selector, Phase::PostCommit)
    }

    async fn evaluate_phase(
        &self,
        selector: &RpcSelector,
        phase: Phase,
        operation_type: &str,
        operation: ValidatedOperation,
        context: &EvaluationContext,
    ) -> std::result::Result<ValidatedOperation, Status> {
        let Some(plans) = self.plan.bindings(selector, phase) else {
            return Ok(operation);
        };

        let mut operation = operation;
        for plan in plans {
            let interceptor_view = self
                .codec
                .decode_bytes_to_interceptor_json(operation_type, &operation.encoded)
                .map_err(|err| Status::internal(err.to_string()))?;
            let result = evaluate_plan(plan, interceptor_view, context).await;
            let result = match result {
                Ok(result) => result,
                Err(err) => {
                    apply_failure_policy(plan, &err)?;
                    continue;
                }
            };
            operation =
                apply_evaluation_result(&self.codec, operation_type, plan, &result, operation)?;
        }
        Ok(operation)
    }
}

fn apply_evaluation_result(
    codec: &ProtoJsonCodec,
    operation_type: &str,
    plan: &BindingPlan,
    result: &InterceptorResult,
    operation: ValidatedOperation,
) -> std::result::Result<ValidatedOperation, Status> {
    if let Err(err) = validate_result_contract(plan, result) {
        apply_failure_policy(plan, &err)?;
        return Ok(operation);
    }

    if !result.allowed {
        let reason = if result.reason.trim().is_empty() {
            "operation denied by gateway interceptor".to_string()
        } else {
            result.reason.clone()
        };
        emit_evaluation_metrics(plan, "deny", 0);
        emit_evaluation_log(plan, result, "deny", 0);
        return Err(status_from_result(result, reason));
    }

    if plan.phase == Phase::ModifyOperation && !result.patches.is_empty() {
        let patch_count = result.patches.len();
        if let Err(err) = validate_patch_visibility(codec, operation_type, &result.patches) {
            apply_failure_policy(plan, &err)?;
            return Ok(operation);
        }
        match operation.apply_patches(codec, operation_type, &result.patches) {
            Ok(candidate) => {
                emit_evaluation_metrics(plan, "allow", patch_count);
                emit_evaluation_log(plan, result, "allow", patch_count);
                Ok(candidate)
            }
            Err(err) => {
                apply_failure_policy(plan, &err)?;
                Ok(operation)
            }
        }
    } else {
        emit_evaluation_metrics(plan, "allow", 0);
        emit_evaluation_log(plan, result, "allow", 0);
        Ok(operation)
    }
}

fn validate_patch_visibility(
    codec: &ProtoJsonCodec,
    operation_type: &str,
    patches: &[JsonPatch],
) -> Result<()> {
    for patch in patches {
        codec.ensure_interceptor_patch_path_visible(operation_type, &patch.path)?;
        if !patch.from.is_empty() {
            codec.ensure_interceptor_patch_path_visible(operation_type, &patch.from)?;
        }
    }
    Ok(())
}

async fn evaluate_plan(
    plan: &BindingPlan,
    operation: Value,
    context: &EvaluationContext,
) -> Result<InterceptorResult> {
    let operation = json_to_struct(operation)?;
    let current_state = if plan.phase == Phase::Validate {
        context
            .validate_current_state
            .clone()
            .map(json_to_struct)
            .transpose()?
    } else {
        None
    };
    let request = InterceptorEvaluation {
        interceptor_name: plan.interceptor_name.clone(),
        binding_id: plan.binding_id.clone(),
        service: plan.selector.service.clone(),
        method: plan.selector.method.clone(),
        principal: context.principal.clone().into_iter().collect(),
        phase: Some(phase_evaluation(plan.phase, operation, current_state)),
    };

    let start = Instant::now();
    let result = tokio::time::timeout(
        plan.timeout,
        plan.client.clone().evaluate(Request::new(request)),
    )
    .await
    .map_err(|_| InterceptorError::Transport("evaluation timed out".to_string()))?
    .map_err(|status| InterceptorError::Transport(status.to_string()))?
    .into_inner();
    let encoded_len = result.encoded_len();
    histogram!("openshell_gateway_interceptor_latency_seconds")
        .record(start.elapsed().as_secs_f64());
    if encoded_len > plan.max_response_bytes {
        return Err(InterceptorError::InvalidResult(format!(
            "interceptor response exceeded max_response_bytes ({} > {})",
            encoded_len, plan.max_response_bytes
        )));
    }
    Ok(result)
}

fn phase_evaluation(
    phase: Phase,
    proposed_operation: Struct,
    current_state: Option<Struct>,
) -> interceptor_evaluation::Phase {
    match phase {
        Phase::ModifyOperation => {
            interceptor_evaluation::Phase::ModifyOperation(ModifyOperationEvaluation {
                proposed_operation: Some(proposed_operation),
            })
        }
        Phase::Validate => interceptor_evaluation::Phase::Validate(ValidateEvaluation {
            proposed_operation: Some(proposed_operation),
            current_state,
        }),
        Phase::PostCommit => interceptor_evaluation::Phase::PostCommit(PostCommitEvaluation {
            committed_response: Some(proposed_operation),
        }),
    }
}

fn apply_failure_policy(
    plan: &BindingPlan,
    err: &InterceptorError,
) -> std::result::Result<(), Status> {
    match plan.failure_policy {
        FailurePolicy::FailClosed => {
            warn!(
                interceptor = %plan.interceptor_name,
                binding_id = %plan.binding_id,
                phase = plan.phase.as_str(),
                error = %err,
                "gateway interceptor failed closed"
            );
            counter!("openshell_gateway_interceptor_fail_closed_total").increment(1);
            Err(Status::permission_denied(format!(
                "gateway interceptor '{}' failed closed: {err}",
                plan.interceptor_name
            )))
        }
        FailurePolicy::FailOpen => {
            warn!(
                interceptor = %plan.interceptor_name,
                binding_id = %plan.binding_id,
                phase = plan.phase.as_str(),
                error = %err,
                "gateway interceptor failed open"
            );
            counter!("openshell_gateway_interceptor_fail_open_total").increment(1);
            Ok(())
        }
    }
}

fn validate_result_contract(plan: &BindingPlan, result: &InterceptorResult) -> Result<()> {
    if result.patches.len() > plan.max_patches {
        return Err(InterceptorError::InvalidResult(format!(
            "interceptor returned too many patches ({} > {})",
            result.patches.len(),
            plan.max_patches
        )));
    }
    if plan.phase != Phase::ModifyOperation && !result.patches.is_empty() {
        return Err(InterceptorError::InvalidResult(format!(
            "patches are invalid during {}",
            plan.phase.as_str()
        )));
    }
    if plan.phase == Phase::PostCommit && (!result.allowed || !result.patches.is_empty()) {
        return Err(InterceptorError::InvalidResult(
            "post_commit cannot deny or mutate operations".to_string(),
        ));
    }
    Ok(())
}

fn status_from_result(result: &InterceptorResult, reason: String) -> Status {
    let code = grpc_code_from_name(&result.status_code).unwrap_or(Code::PermissionDenied);
    Status::new(code, reason)
}

fn grpc_code_from_name(value: &str) -> Option<Code> {
    match value.trim().to_ascii_uppercase().as_str() {
        "OK" => Some(Code::Ok),
        "CANCELLED" => Some(Code::Cancelled),
        "UNKNOWN" => Some(Code::Unknown),
        "INVALID_ARGUMENT" => Some(Code::InvalidArgument),
        "DEADLINE_EXCEEDED" => Some(Code::DeadlineExceeded),
        "NOT_FOUND" => Some(Code::NotFound),
        "ALREADY_EXISTS" => Some(Code::AlreadyExists),
        "PERMISSION_DENIED" => Some(Code::PermissionDenied),
        "RESOURCE_EXHAUSTED" => Some(Code::ResourceExhausted),
        "FAILED_PRECONDITION" => Some(Code::FailedPrecondition),
        "ABORTED" => Some(Code::Aborted),
        "OUT_OF_RANGE" => Some(Code::OutOfRange),
        "UNIMPLEMENTED" => Some(Code::Unimplemented),
        "INTERNAL" => Some(Code::Internal),
        "UNAVAILABLE" => Some(Code::Unavailable),
        "DATA_LOSS" => Some(Code::DataLoss),
        "UNAUTHENTICATED" => Some(Code::Unauthenticated),
        _ => None,
    }
}

fn json_patch_operations(patches: &[JsonPatch]) -> Result<Vec<PatchOperation>> {
    let mut raw = Vec::with_capacity(patches.len());
    for patch in patches {
        let mut op = Map::new();
        op.insert("op".to_string(), Value::String(patch.op.clone()));
        op.insert("path".to_string(), Value::String(patch.path.clone()));
        if !patch.from.is_empty() {
            op.insert("from".to_string(), Value::String(patch.from.clone()));
        }
        if let Some(value) = patch.value.as_ref() {
            op.insert(
                "value".to_string(),
                openshell_core::proto_struct::value_to_json(value),
            );
        }
        raw.push(Value::Object(op));
    }
    serde_json::from_value(Value::Array(raw))
        .map_err(|e| InterceptorError::InvalidResult(format!("invalid JSON patch: {e}")))
}

fn apply_json_patches(operation: &Value, patches: &[JsonPatch]) -> Result<Value> {
    let patch_ops = json_patch_operations(patches)?;
    let mut candidate = operation.clone();
    patch(&mut candidate, &patch_ops)
        .map_err(|err| InterceptorError::InvalidResult(format!("invalid JSON patch: {err}")))?;
    Ok(candidate)
}

fn emit_evaluation_metrics(plan: &BindingPlan, result: &str, patch_count: usize) {
    counter!(
        "openshell_gateway_interceptor_evaluations_total",
        "decision" => result.to_string(),
        "interceptor" => plan.interceptor_name.clone(),
        "binding_id" => plan.binding_id.clone(),
    )
    .increment(1);
    if patch_count > 0 {
        counter!(
            "openshell_gateway_interceptor_patches_total",
            "interceptor" => plan.interceptor_name.clone(),
            "binding_id" => plan.binding_id.clone(),
        )
        .increment(patch_count as u64);
    }
}

fn emit_evaluation_log(
    plan: &BindingPlan,
    result: &InterceptorResult,
    decision: &str,
    patch_count: usize,
) {
    info!(
        interceptor = %plan.interceptor_name,
        binding_id = %plan.binding_id,
        phase = plan.phase.as_str(),
        service = %plan.selector.service,
        method = %plan.selector.method,
        decision,
        patch_count,
        log_annotations = ?result.log_annotations,
        "gateway interceptor evaluated"
    );
}

#[derive(Debug, Clone)]
struct GrpcFrame {
    compressed: bool,
    message: Vec<u8>,
}

impl GrpcFrame {
    fn decode(body: &[u8]) -> std::result::Result<Self, Status> {
        if body.len() < GRPC_HEADER_LEN {
            return Err(Status::invalid_argument("gRPC frame is too short"));
        }
        let compressed = body[0] != 0;
        if compressed {
            return Err(Status::unimplemented(
                "gateway interceptors do not support compressed gRPC frames",
            ));
        }
        let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        if body.len() != GRPC_HEADER_LEN + len {
            return Err(Status::invalid_argument(
                "gRPC body must contain exactly one frame",
            ));
        }
        Ok(Self {
            compressed,
            message: body[GRPC_HEADER_LEN..].to_vec(),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.compressed {
            return Err(InterceptorError::Transcode(
                "compressed gRPC frames are not supported".to_string(),
            ));
        }
        let len = u32::try_from(self.message.len())
            .map_err(|_| InterceptorError::Transcode("message exceeds u32".to_string()))?;
        let mut out = Vec::with_capacity(GRPC_HEADER_LEN + self.message.len());
        out.push(0);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.message);
        Ok(out)
    }
}

fn json_to_struct(value: Value) -> Result<Struct> {
    match value {
        Value::Object(fields) => Ok(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
                .collect::<Result<_>>()?,
        }),
        _ => Err(InterceptorError::Transcode(
            "operation JSON must be an object".to_string(),
        )),
    }
}

fn json_to_protobuf_value(value: Value) -> Result<prost_types::Value> {
    let kind = match value {
        Value::Null => prost_types::value::Kind::NullValue(0),
        Value::Bool(value) => prost_types::value::Kind::BoolValue(value),
        Value::Number(value) => prost_types::value::Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| InterceptorError::Transcode("invalid JSON number".to_string()))?,
        ),
        Value::String(value) => prost_types::value::Kind::StringValue(value),
        Value::Array(values) => prost_types::value::Kind::ListValue(prost_types::ListValue {
            values: values
                .into_iter()
                .map(json_to_protobuf_value)
                .collect::<Result<_>>()?,
        }),
        Value::Object(fields) => prost_types::value::Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(key, value)| json_to_protobuf_value(value).map(|value| (key, value)))
                .collect::<Result<_>>()?,
        }),
    };
    Ok(prost_types::Value { kind: Some(kind) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_client::GatewayInterceptorClient;
    use openshell_core::proto::{
        CreateProviderRequest, CreateSandboxRequest, Provider, SandboxSpec, SandboxTemplate,
        UpdateConfigRequest,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };
    use tonic::transport::Channel;
    use tracing_subscriber::layer::SubscriberExt;

    use crate::plan::{DEFAULT_MAX_PATCHES, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT};

    #[derive(Clone)]
    struct TraceBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TraceBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AtomicCounter(Arc<AtomicU64>);

    impl metrics::CounterFn for AtomicCounter {
        fn increment(&self, value: u64) {
            self.0.fetch_add(value, Ordering::Relaxed);
        }

        fn absolute(&self, value: u64) {
            self.0.fetch_max(value, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Default)]
    struct TestRecorder {
        evaluations: Arc<AtomicU64>,
        patches: Arc<AtomicU64>,
        fail_open: Arc<AtomicU64>,
        fail_closed: Arc<AtomicU64>,
    }

    impl metrics::Recorder for TestRecorder {
        fn describe_counter(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            let counter = match key.name() {
                "openshell_gateway_interceptor_evaluations_total" => &self.evaluations,
                "openshell_gateway_interceptor_patches_total" => &self.patches,
                "openshell_gateway_interceptor_fail_open_total" => &self.fail_open,
                "openshell_gateway_interceptor_fail_closed_total" => &self.fail_closed,
                _ => return metrics::Counter::noop(),
            };
            metrics::Counter::from_arc(Arc::new(AtomicCounter(counter.clone())))
        }

        fn register_gauge(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    impl TestRecorder {
        fn count(counter: &AtomicU64) -> u64 {
            counter.load(Ordering::Relaxed)
        }
    }

    fn test_modify_plan(failure_policy: FailurePolicy) -> BindingPlan {
        BindingPlan {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            selector: RpcSelector {
                service: "openshell.v1.OpenShell".to_string(),
                method: "UpdateConfig".to_string(),
            },
            phase: Phase::ModifyOperation,
            failure_policy,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_patches: DEFAULT_MAX_PATCHES,
            client: GatewayInterceptorClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
        }
    }

    fn patch(op: &str, path: &str, value: Value) -> JsonPatch {
        JsonPatch {
            op: op.to_string(),
            path: path.to_string(),
            value: Some(json_to_protobuf_value(value).unwrap()),
            from: String::new(),
        }
    }

    fn allowed_result(patches: Vec<JsonPatch>) -> InterceptorResult {
        InterceptorResult {
            allowed: true,
            patches,
            ..InterceptorResult::default()
        }
    }

    fn create_provider_operation(codec: &ProtoJsonCodec) -> ValidatedOperation {
        let request = CreateProviderRequest {
            provider: Some(Provider {
                r#type: "github".to_string(),
                credentials: HashMap::from([(
                    "GITHUB_TOKEN".to_string(),
                    "secret-value".to_string(),
                )]),
                config: HashMap::from([("region".to_string(), "old".to_string())]),
                ..Provider::default()
            }),
            workspace: String::new(),
        };
        let json = codec
            .decode_message_to_json("openshell.v1.CreateProviderRequest", &request)
            .unwrap();
        ValidatedOperation::new(codec, "openshell.v1.CreateProviderRequest", json).unwrap()
    }

    #[tokio::test]
    async fn secret_patch_path_fails_closed() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let operation = create_provider_operation(&codec);
        let result = allowed_result(vec![patch(
            "replace",
            "/provider/credentials/GITHUB_TOKEN",
            json!("replacement"),
        )]);

        let status = apply_evaluation_result(
            &codec,
            "openshell.v1.CreateProviderRequest",
            &test_modify_plan(FailurePolicy::FailClosed),
            &result,
            operation,
        )
        .expect_err("secret patch must fail closed");

        assert!(status.message().contains("omitted secret field"));
    }

    #[tokio::test]
    async fn secret_patch_path_fails_open_to_the_unchanged_operation() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let operation = create_provider_operation(&codec);
        let prior = operation.clone();
        let result = allowed_result(vec![patch(
            "remove",
            "/provider/credentials/GITHUB_TOKEN",
            Value::Null,
        )]);

        let outcome = apply_evaluation_result(
            &codec,
            "openshell.v1.CreateProviderRequest",
            &test_modify_plan(FailurePolicy::FailOpen),
            &result,
            operation,
        )
        .unwrap();

        assert_eq!(outcome, prior);
    }

    #[tokio::test]
    async fn secret_patch_from_path_is_rejected() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let operation = create_provider_operation(&codec);
        let result = allowed_result(vec![JsonPatch {
            op: "copy".to_string(),
            path: "/provider/config/copied".to_string(),
            value: None,
            from: "/provider/credentials/GITHUB_TOKEN".to_string(),
        }]);

        let status = apply_evaluation_result(
            &codec,
            "openshell.v1.CreateProviderRequest",
            &test_modify_plan(FailurePolicy::FailClosed),
            &result,
            operation,
        )
        .expect_err("secret patch source must fail closed");

        assert!(status.message().contains("omitted secret field"));
    }

    #[tokio::test]
    async fn non_secret_patch_preserves_authoritative_credentials() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let operation = create_provider_operation(&codec);
        let result = allowed_result(vec![patch(
            "replace",
            "/provider/config/region",
            json!("new"),
        )]);

        let outcome = apply_evaluation_result(
            &codec,
            "openshell.v1.CreateProviderRequest",
            &test_modify_plan(FailurePolicy::FailClosed),
            &result,
            operation,
        )
        .unwrap();
        let decoded = CreateProviderRequest::decode(outcome.encoded.as_slice()).unwrap();
        let provider = decoded.provider.unwrap();

        assert_eq!(provider.config["region"], "new");
        assert_eq!(provider.credentials["GITHUB_TOKEN"], "secret-value");
    }

    #[test]
    fn phase_evaluations_use_the_matching_oneof_variant() {
        let operation = json_to_struct(json!({"name": "demo"})).unwrap();

        let modify = phase_evaluation(Phase::ModifyOperation, operation.clone(), None);
        let interceptor_evaluation::Phase::ModifyOperation(payload) = modify else {
            panic!("expected modify_operation payload");
        };
        assert_eq!(payload.proposed_operation, Some(operation.clone()));

        let validate = phase_evaluation(Phase::Validate, operation.clone(), None);
        let interceptor_evaluation::Phase::Validate(payload) = validate else {
            panic!("expected validate payload");
        };
        assert_eq!(payload.proposed_operation, Some(operation.clone()));
        assert!(payload.current_state.is_none());

        let validate =
            phase_evaluation(Phase::Validate, operation.clone(), Some(Struct::default()));
        let interceptor_evaluation::Phase::Validate(payload) = validate else {
            panic!("expected validate payload");
        };
        assert_eq!(payload.current_state, Some(Struct::default()));

        let current_state = json_to_struct(json!({"resourceVersion": "7"})).unwrap();
        let validate = phase_evaluation(
            Phase::Validate,
            operation.clone(),
            Some(current_state.clone()),
        );
        let interceptor_evaluation::Phase::Validate(payload) = validate else {
            panic!("expected validate payload");
        };
        assert_eq!(payload.current_state, Some(current_state.clone()));

        let post_commit =
            phase_evaluation(Phase::PostCommit, operation.clone(), Some(current_state));
        let interceptor_evaluation::Phase::PostCommit(payload) = post_commit else {
            panic!("expected post_commit payload");
        };
        assert_eq!(payload.committed_response, Some(operation));
    }

    #[tokio::test]
    async fn evaluation_log_emits_structured_log_annotations() {
        let log_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = TraceBuf(log_buf.clone());
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time();
        let subscriber = tracing_subscriber::registry().with(fmt_layer);
        let plan = BindingPlan {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            selector: RpcSelector {
                service: "openshell.v1.OpenShell".to_string(),
                method: "CreateSandbox".to_string(),
            },
            phase: Phase::ModifyOperation,
            failure_policy: FailurePolicy::FailClosed,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_patches: DEFAULT_MAX_PATCHES,
            client: GatewayInterceptorClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
        };
        let result = InterceptorResult {
            allowed: true,
            log_annotations: HashMap::from([
                (
                    "correlation_id".to_string(),
                    "governance:create-sandbox:demo".to_string(),
                ),
                ("policy_hash".to_string(), "abc123".to_string()),
            ]),
            ..InterceptorResult::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            // Other parallel tests may register this callsite while no subscriber
            // is active. Refresh the process-wide cache after installing this
            // thread-local subscriber so the event cannot remain disabled.
            tracing::callsite::rebuild_interest_cache();
            emit_evaluation_log(&plan, &result, "allow", 2);
        });

        let output = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("gateway interceptor evaluated"));
        assert!(output.contains("log_annotations"));
        assert!(output.contains("correlation_id"));
        assert!(output.contains("governance:create-sandbox:demo"));
        assert!(output.contains("policy_hash"));
    }

    #[tokio::test]
    async fn request_middleware_canonicalizes_ambiguous_oneof_before_dispatch() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let routes =
            routes::OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)
                .unwrap();
        let runtime = GatewayInterceptorRuntime {
            plan: Arc::new(ExecutionPlan::empty(routes)),
            codec: codec.clone(),
        };
        let body = GrpcFrame {
            compressed: false,
            message: vec![0x3a, 0x04, 0x0a, 0x00, 0x1a, 0x00],
        }
        .encode()
        .unwrap();

        let intercepted = runtime
            .evaluate_request(
                "/openshell.v1.OpenShell/UpdateConfig",
                &body,
                &EvaluationContext {
                    principal: BTreeMap::new(),
                    validate_current_state: None,
                },
            )
            .await
            .unwrap();
        let frame = GrpcFrame::decode(&intercepted.body).unwrap();
        let json = codec
            .decode_bytes_to_json("openshell.v1.UpdateConfigRequest", &frame.message)
            .unwrap();

        assert_eq!(json["mergeOperations"][0], json!({"removeRule": {}}));
    }

    #[tokio::test]
    async fn request_middleware_accepts_semantically_equal_map_encodings() {
        let codec = ProtoJsonCodec::openshell().unwrap();
        let routes =
            routes::OpenShellRouteIndex::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)
                .unwrap();
        let runtime = GatewayInterceptorRuntime {
            plan: Arc::new(ExecutionPlan::empty(routes)),
            codec: codec.clone(),
        };
        let request = UpdateConfigRequest {
            name: "demo".to_string(),
            expected_resource_version: u64::MAX - 1,
            annotations: HashMap::from([
                ("policy-hash".to_string(), "sha256:v2:abc".to_string()),
                ("policy-signature".to_string(), "signature".to_string()),
                ("policy-signature-kid".to_string(), "kid".to_string()),
                ("correlation-id".to_string(), "reload-1".to_string()),
            ]),
            ..UpdateConfigRequest::default()
        };
        let body = GrpcFrame {
            compressed: false,
            message: request.encode_to_vec(),
        }
        .encode()
        .unwrap();

        let intercepted = runtime
            .evaluate_request(
                "/openshell.v1.OpenShell/UpdateConfig",
                &body,
                &EvaluationContext {
                    principal: BTreeMap::new(),
                    validate_current_state: None,
                },
            )
            .await
            .unwrap();
        let frame = GrpcFrame::decode(&intercepted.body).unwrap();
        let decoded = UpdateConfigRequest::decode(frame.message.as_slice()).unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn dynamic_round_trip_uses_protobuf_json_for_struct_fields() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    resources: Some(
                        json_to_struct(json!({
                            "limits": {
                                "cpu": "2",
                                "memory": "4Gi"
                            }
                        }))
                        .unwrap(),
                    ),
                    driver_config: Some(
                        json_to_struct(json!({
                            "docker": {
                                "userns": "host"
                            }
                        }))
                        .unwrap(),
                    ),
                    ..SandboxTemplate::default()
                }),
                ..SandboxSpec::default()
            }),
            name: "demo".to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            workspace: String::new(),
        };

        let bytes = request.encode_to_vec();
        let json = codec
            .decode_bytes_to_json("openshell.v1.CreateSandboxRequest", &bytes)
            .unwrap();

        assert_eq!(json["spec"]["template"]["resources"]["limits"]["cpu"], "2");
        assert_eq!(
            json["spec"]["template"]["driverConfig"]["docker"]["userns"],
            "host"
        );
        assert!(
            json["spec"]["template"]["resources"]
                .get("fields")
                .is_none()
        );

        let encoded = codec
            .encode_json_to_message("openshell.v1.CreateSandboxRequest", &json)
            .unwrap();
        let decoded = CreateSandboxRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[tokio::test]
    async fn invalid_modify_patch_honors_fail_open_without_mutating_operation() {
        let plan = BindingPlan {
            interceptor_name: "test".to_string(),
            binding_id: "binding".to_string(),
            selector: RpcSelector {
                service: "openshell.v1.OpenShell".to_string(),
                method: "CreateSandbox".to_string(),
            },
            phase: Phase::ModifyOperation,
            failure_policy: FailurePolicy::FailOpen,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_patches: DEFAULT_MAX_PATCHES,
            client: GatewayInterceptorClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
        };
        let operation = json!({ "name": "demo" });
        let result = InterceptorResult {
            allowed: true,
            patches: vec![JsonPatch {
                op: "replace".to_string(),
                path: "/missing".to_string(),
                value: Some(prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("value".to_string())),
                }),
                from: String::new(),
            }],
            ..InterceptorResult::default()
        };

        let err = apply_json_patches(&operation, &result.patches).unwrap_err();
        apply_failure_policy(&plan, &err).unwrap();
        assert_eq!(operation, json!({ "name": "demo" }));
    }

    #[test]
    fn validated_operation_rejects_message_repeated_and_enum_type_errors() {
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let cases = [
            (
                "openshell.v1.CreateSandboxRequest",
                json!({"name": "demo", "spec": {}}),
                patch("replace", "/spec", json!("not-a-message")),
            ),
            (
                "openshell.v1.CreateSandboxRequest",
                json!({"name": "demo", "spec": {"providers": []}}),
                patch("replace", "/spec/providers", json!({"provider": "github"})),
            ),
            (
                "openshell.v1.ReportPolicyStatusRequest",
                json!({
                    "sandboxId": "sandbox-id",
                    "version": 1,
                    "status": "POLICY_STATUS_LOADED"
                }),
                patch("replace", "/status", json!("POLICY_STATUS_UNKNOWN")),
            ),
        ];

        for (type_name, json, invalid_patch) in cases {
            let operation = ValidatedOperation::new(&codec, type_name, json).unwrap();
            let err = operation
                .apply_patches(&codec, type_name, &[invalid_patch])
                .expect_err("wrong-type patch must not produce a validated operation");

            assert!(matches!(err, InterceptorError::InvalidResult(_)));
            assert!(err.to_string().contains("patched operation is not valid"));
        }
    }

    #[tokio::test]
    async fn wrong_type_patch_fails_open_to_exact_prior_operation_and_metrics() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            json!({"name": "demo", "expectedResourceVersion": "7"}),
        )
        .unwrap();
        let prior = operation.clone();
        let plan = test_modify_plan(FailurePolicy::FailOpen);
        let result = allowed_result(vec![patch(
            "replace",
            "/expectedResourceVersion",
            json!("not-a-number"),
        )]);
        let recorder = TestRecorder::default();

        let outcome = metrics::with_local_recorder(&recorder, || {
            apply_evaluation_result(
                &codec,
                "openshell.v1.UpdateConfigRequest",
                &plan,
                &result,
                operation,
            )
        })
        .unwrap();

        assert_eq!(outcome, prior);
        assert_eq!(TestRecorder::count(&recorder.fail_open), 1);
        assert_eq!(TestRecorder::count(&recorder.fail_closed), 0);
        assert_eq!(TestRecorder::count(&recorder.evaluations), 0);
        assert_eq!(TestRecorder::count(&recorder.patches), 0);
    }

    #[tokio::test]
    async fn wrong_type_patch_fails_closed_before_dispatch_and_metrics() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            json!({"name": "demo", "expectedResourceVersion": "7"}),
        )
        .unwrap();
        let plan = test_modify_plan(FailurePolicy::FailClosed);
        let result = allowed_result(vec![patch(
            "replace",
            "/expectedResourceVersion",
            json!("not-a-number"),
        )]);
        let recorder = TestRecorder::default();

        let status = metrics::with_local_recorder(&recorder, || {
            apply_evaluation_result(
                &codec,
                "openshell.v1.UpdateConfigRequest",
                &plan,
                &result,
                operation,
            )
        })
        .expect_err("fail-closed invalid candidate must stop dispatch");

        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("patched operation is not valid"));
        assert_eq!(TestRecorder::count(&recorder.fail_open), 0);
        assert_eq!(TestRecorder::count(&recorder.fail_closed), 1);
        assert_eq!(TestRecorder::count(&recorder.evaluations), 0);
        assert_eq!(TestRecorder::count(&recorder.patches), 0);
    }

    #[tokio::test]
    async fn invalid_patch_list_is_atomic() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            json!({"name": "demo", "expectedResourceVersion": "7"}),
        )
        .unwrap();
        let prior = operation.clone();
        let result = allowed_result(vec![
            patch("replace", "/name", json!("partially-mutated")),
            patch("replace", "/expectedResourceVersion", json!("not-a-number")),
        ]);

        let outcome = apply_evaluation_result(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            &test_modify_plan(FailurePolicy::FailOpen),
            &result,
            operation,
        )
        .unwrap();

        assert_eq!(outcome, prior);
        assert_eq!(outcome.json["name"], "demo");
    }

    #[tokio::test]
    async fn later_binding_sees_pre_binding_value_after_invalid_candidate_fails_open() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            json!({"name": "demo", "expectedResourceVersion": "7"}),
        )
        .unwrap();
        let plan = test_modify_plan(FailurePolicy::FailOpen);
        let invalid_first = allowed_result(vec![
            patch("replace", "/name", json!("rejected-candidate")),
            patch("replace", "/expectedResourceVersion", json!("not-a-number")),
        ]);
        let second = allowed_result(vec![
            patch("test", "/name", json!("demo")),
            patch("replace", "/name", json!("accepted-candidate")),
        ]);

        let operation = apply_evaluation_result(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            &plan,
            &invalid_first,
            operation,
        )
        .unwrap();
        let operation = apply_evaluation_result(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            &plan,
            &second,
            operation,
        )
        .unwrap();

        assert_eq!(operation.json["name"], "accepted-candidate");
        let decoded = UpdateConfigRequest::decode(operation.encoded.as_slice()).unwrap();
        assert_eq!(decoded.name, "accepted-candidate");
        assert_eq!(decoded.expected_resource_version, 7);
    }

    #[tokio::test]
    async fn ambiguous_oneof_patch_obeys_binding_failure_policy() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.PolicyMergeOperation",
            json!({"addRule": {}}),
        )
        .unwrap();
        let result = allowed_result(vec![patch("add", "/removeRule", json!({}))]);

        let fail_open = apply_evaluation_result(
            &codec,
            "openshell.v1.PolicyMergeOperation",
            &test_modify_plan(FailurePolicy::FailOpen),
            &result,
            operation.clone(),
        )
        .unwrap();
        let fail_closed = apply_evaluation_result(
            &codec,
            "openshell.v1.PolicyMergeOperation",
            &test_modify_plan(FailurePolicy::FailClosed),
            &result,
            operation.clone(),
        )
        .expect_err("ambiguous oneof candidate must fail closed");

        assert_eq!(fail_open, operation);
        assert_eq!(fail_closed.code(), Code::PermissionDenied);
        assert!(fail_closed.message().contains("oneof 'operation'"));
    }

    #[tokio::test]
    async fn accepted_candidate_updates_encoded_operation_and_patch_metrics() {
        tokio::task::yield_now().await;
        let codec =
            ProtoJsonCodec::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
        let operation = ValidatedOperation::new(
            &codec,
            "openshell.v1.UpdateConfigRequest",
            json!({"name": "demo", "expectedResourceVersion": "7"}),
        )
        .unwrap();
        let result = allowed_result(vec![patch("replace", "/name", json!("accepted"))]);
        let recorder = TestRecorder::default();

        let operation = metrics::with_local_recorder(&recorder, || {
            apply_evaluation_result(
                &codec,
                "openshell.v1.UpdateConfigRequest",
                &test_modify_plan(FailurePolicy::FailClosed),
                &result,
                operation,
            )
        })
        .unwrap();

        let decoded = UpdateConfigRequest::decode(operation.encoded.as_slice()).unwrap();
        assert_eq!(decoded.name, "accepted");
        assert_eq!(TestRecorder::count(&recorder.evaluations), 1);
        assert_eq!(TestRecorder::count(&recorder.patches), 1);
        assert_eq!(TestRecorder::count(&recorder.fail_open), 0);
        assert_eq!(TestRecorder::count(&recorder.fail_closed), 0);
    }
}
