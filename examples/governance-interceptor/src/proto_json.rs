// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example-local descriptor-backed protobuf/ProtoJSON conversion.

use std::sync::{Arc, OnceLock};

use prost::Message as _;
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage, MessageDescriptor};
use serde_json::Value;

#[derive(Debug, Clone)]
struct ProtoJsonCodec {
    pool: Arc<DescriptorPool>,
}

impl ProtoJsonCodec {
    fn openshell() -> Result<Self, String> {
        let pool = DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .map_err(|err| format!("decode OpenShell protobuf descriptor set: {err}"))?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    fn decode_message_to_json<M>(&self, type_name: &str, message: &M) -> Result<Value, String>
    where
        M: prost::Message,
    {
        let descriptor = self.message_descriptor(type_name)?;
        let message = DynamicMessage::decode(descriptor, message.encode_to_vec().as_slice())
            .map_err(|err| format!("decode {type_name} protobuf message: {err}"))?;
        serde_json::to_value(message)
            .map_err(|err| format!("serialize {type_name} as ProtoJSON: {err}"))
    }

    fn encode_json_to_message(&self, type_name: &str, value: &Value) -> Result<Vec<u8>, String> {
        let descriptor = self.message_descriptor(type_name)?;
        let encoded_json = serde_json::to_vec(value)
            .map_err(|err| format!("serialize {type_name} JSON before protobuf encoding: {err}"))?;
        let mut deserializer = serde_json::Deserializer::from_slice(&encoded_json);
        let message = DynamicMessage::deserialize_with_options(
            descriptor,
            &mut deserializer,
            &DeserializeOptions::new(),
        )
        .map_err(|err| format!("encode {type_name} from ProtoJSON: {err}"))?;
        deserializer
            .end()
            .map_err(|err| format!("encode {type_name} from ProtoJSON: {err}"))?;
        Ok(message.encode_to_vec())
    }

    fn message_descriptor(&self, type_name: &str) -> Result<MessageDescriptor, String> {
        let normalized = type_name.strip_prefix('.').unwrap_or(type_name);
        self.pool.get_message_by_name(normalized).ok_or_else(|| {
            format!("protobuf message type '{normalized}' was not found in the descriptor set")
        })
    }
}

fn openshell_codec() -> Result<&'static ProtoJsonCodec, String> {
    static CODEC: OnceLock<ProtoJsonCodec> = OnceLock::new();

    if let Some(codec) = CODEC.get() {
        return Ok(codec);
    }

    let codec = ProtoJsonCodec::openshell()?;
    let _ = CODEC.set(codec);
    CODEC
        .get()
        .ok_or_else(|| "initialize OpenShell protobuf codec".to_string())
}

pub(crate) fn decode_message_to_json<M>(type_name: &str, message: &M) -> Result<Value, String>
where
    M: prost::Message,
{
    openshell_codec()?.decode_message_to_json(type_name, message)
}

pub(crate) fn encode_json_to_message(type_name: &str, value: &Value) -> Result<Vec<u8>, String> {
    openshell_codec()?.encode_json_to_message(type_name, value)
}
