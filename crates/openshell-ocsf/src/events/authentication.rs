// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Authentication [3002] event class.

use serde::{Deserialize, Serialize};

use crate::enums::{ActionId, AuthProtocolId, DispositionId};
use crate::events::base_event::BaseEventData;
use crate::objects::{Endpoint, HttpRequest, Service, User};

/// OCSF Authentication Event [3002].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthenticationEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The principal that authenticated, or attempted to.
    pub user: User,

    /// Authentication protocol.
    #[serde(
        rename = "auth_protocol_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_protocol: Option<AuthProtocolId>,

    /// Authentication protocol label (custom when `auth_protocol` is Other).
    #[serde(
        rename = "auth_protocol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_protocol_label: Option<String>,

    /// The service authenticated to.
    pub service: Service,

    /// Source endpoint (connecting peer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,

    /// The request the credential was presented with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_request: Option<HttpRequest>,

    /// Action (Security Control profile).
    #[serde(rename = "action_id", default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionId>,

    /// Disposition.
    #[serde(
        rename = "disposition_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disposition: Option<DispositionId>,
}

impl Serialize for AuthenticationEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{
            insert_enum_pair, insert_enum_pair_custom, insert_optional, insert_required,
        };

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_required!(obj, "user", self.user);
        insert_enum_pair_custom!(
            obj,
            "auth_protocol",
            self.auth_protocol,
            self.auth_protocol_label
        );
        insert_required!(obj, "service", self.service);
        insert_optional!(obj, "src_endpoint", self.src_endpoint);
        insert_optional!(obj, "http_request", self.http_request);
        insert_enum_pair!(obj, "action", self.action);
        insert_enum_pair!(obj, "disposition", self.disposition);

        base_val.serialize(serializer)
    }
}
