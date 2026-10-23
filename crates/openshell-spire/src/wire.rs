// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire messages of the SPIRE agent Delegated Identity API.
//!
//! Transcribed from `proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto`
//! and `proto/spire/api/types/{selector,jwtsvid,spiffeid}.proto` of
//! <https://github.com/spiffe/spire-api-sdk> at tag `v1.15.3` (commit
//! `adb81b3b0fb87a881693d1d42eaf8b2fa1223e42`), Copyright The SPIFFE Authors,
//! licensed under the Apache License, Version 2.0. Only the messages for
//! `FetchJWTSVIDs` and `SubscribeToJWTBundles` are reproduced; field numbers
//! and types are unchanged.

use std::collections::HashMap;

pub const FETCH_JWT_SVIDS: &str =
    "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/FetchJWTSVIDs";
pub const SUBSCRIBE_TO_JWT_BUNDLES: &str =
    "/spire.api.agent.delegatedidentity.v1.DelegatedIdentity/SubscribeToJWTBundles";

/// `spire.api.types.Selector`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Selector {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

/// `spire.api.types.SPIFFEID`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct SpiffeId {
    #[prost(string, tag = "1")]
    pub trust_domain: String,
    #[prost(string, tag = "2")]
    pub path: String,
}

/// `spire.api.types.JWTSVID`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtSvid {
    #[prost(string, tag = "1")]
    pub token: String,
    #[prost(message, optional, tag = "2")]
    pub id: Option<SpiffeId>,
    #[prost(int64, tag = "3")]
    pub expires_at: i64,
    #[prost(int64, tag = "4")]
    pub issued_at: i64,
    #[prost(string, tag = "5")]
    pub hint: String,
}

/// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsRequest`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct FetchJwtSvidsRequest {
    #[prost(string, repeated, tag = "1")]
    pub audience: Vec<String>,
    #[prost(message, repeated, tag = "2")]
    pub selectors: Vec<Selector>,
    #[prost(int32, tag = "3")]
    pub pid: i32,
}

/// `spire.api.agent.delegatedidentity.v1.FetchJWTSVIDsResponse`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct FetchJwtSvidsResponse {
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<JwtSvid>,
}

/// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesRequest`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct SubscribeToJwtBundlesRequest {}

/// `spire.api.agent.delegatedidentity.v1.SubscribeToJWTBundlesResponse`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct SubscribeToJwtBundlesResponse {
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: HashMap<String, Vec<u8>>,
}
