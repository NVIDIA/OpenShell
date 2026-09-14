// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared AIP-158 pagination validation and opaque continuation-token codec.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_core::proto::pagination::v1::{
    ObjectCursor as ProtoObjectCursor, PageToken, PolicyCursor, ProfileCursor, page_token::Cursor,
};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::persistence::ObjectCursor;

const TOKEN_VERSION: u32 = 1;
pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 1000;

/// Validated pagination state for one list request.
#[derive(Debug)]
pub struct Pagination {
    page_size: u32,
    method: &'static str,
    request_fingerprint: Vec<u8>,
    cursor: Option<Cursor>,
}

impl Pagination {
    pub fn new(
        page_size: i32,
        page_token: &str,
        method: &'static str,
        request_parameters: &[&str],
    ) -> Result<Self, Status> {
        if page_size < 0 {
            return Err(Status::invalid_argument("page_size must not be negative"));
        }
        let page_size = if page_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            u32::try_from(page_size)
                .expect("a positive i32 always fits in u32")
                .min(MAX_PAGE_SIZE)
        };
        let request_fingerprint = fingerprint(request_parameters);
        let cursor = if page_token.is_empty() {
            None
        } else {
            let bytes = URL_SAFE_NO_PAD
                .decode(page_token)
                .map_err(|_| Status::invalid_argument("page_token is malformed"))?;
            let token = PageToken::decode(bytes.as_slice())
                .map_err(|_| Status::invalid_argument("page_token is malformed"))?;
            if token.version != TOKEN_VERSION
                || token.method != method
                || token.request_fingerprint != request_fingerprint
            {
                return Err(Status::invalid_argument(
                    "page_token does not match this list request",
                ));
            }
            token.cursor
        };

        Ok(Self {
            page_size,
            method,
            request_fingerprint,
            cursor,
        })
    }

    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn object_cursor(&self) -> Result<Option<ObjectCursor>, Status> {
        match &self.cursor {
            None => Ok(None),
            Some(Cursor::Object(cursor)) => Ok(Some(ObjectCursor {
                created_at_ms: cursor.created_at_ms,
                name: cursor.name.clone(),
                workspace: cursor.workspace.clone(),
                id: cursor.id.clone(),
            })),
            Some(_) => Err(Status::invalid_argument(
                "page_token has the wrong cursor type",
            )),
        }
    }

    pub fn policy_cursor(&self) -> Result<Option<i64>, Status> {
        match &self.cursor {
            None => Ok(None),
            Some(Cursor::Policy(cursor)) => Ok(Some(cursor.version)),
            Some(_) => Err(Status::invalid_argument(
                "page_token has the wrong cursor type",
            )),
        }
    }

    pub fn profile_cursor(&self) -> Result<Option<&str>, Status> {
        match &self.cursor {
            None => Ok(None),
            Some(Cursor::Profile(cursor)) => Ok(Some(&cursor.key)),
            Some(_) => Err(Status::invalid_argument(
                "page_token has the wrong cursor type",
            )),
        }
    }

    pub fn next_object_token(&self, cursor: Option<&ObjectCursor>) -> String {
        cursor.map_or_else(String::new, |cursor| {
            self.encode(Cursor::Object(ProtoObjectCursor {
                created_at_ms: cursor.created_at_ms,
                name: cursor.name.clone(),
                workspace: cursor.workspace.clone(),
                id: cursor.id.clone(),
            }))
        })
    }

    pub fn next_policy_token(&self, version: Option<i64>) -> String {
        version.map_or_else(String::new, |version| {
            self.encode(Cursor::Policy(PolicyCursor { version }))
        })
    }

    pub fn next_profile_token(&self, key: Option<&str>) -> String {
        key.map_or_else(String::new, |key| {
            self.encode(Cursor::Profile(ProfileCursor {
                key: key.to_string(),
            }))
        })
    }

    fn encode(&self, cursor: Cursor) -> String {
        URL_SAFE_NO_PAD.encode(
            PageToken {
                version: TOKEN_VERSION,
                method: self.method.to_string(),
                request_fingerprint: self.request_fingerprint.clone(),
                cursor: Some(cursor),
            }
            .encode_to_vec(),
        )
    }
}

fn fingerprint(parameters: &[&str]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for parameter in parameters {
        hasher.update(
            u64::try_from(parameter.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(parameter.as_bytes());
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_defaults_clamps_and_rejects_negative_values() {
        assert_eq!(
            Pagination::new(0, "", "list", &[]).unwrap().page_size(),
            100
        );
        assert_eq!(
            Pagination::new(1500, "", "list", &[]).unwrap().page_size(),
            1000
        );
        assert_eq!(
            Pagination::new(-1, "", "list", &[]).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn object_token_round_trips_and_allows_page_size_changes() {
        let first = Pagination::new(10, "", "sandboxes", &["default", "env=prod"]).unwrap();
        let cursor = ObjectCursor {
            created_at_ms: 42,
            name: "sandbox".into(),
            workspace: "default".into(),
            id: "id".into(),
        };
        let token = first.next_object_token(Some(&cursor));
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );

        let next = Pagination::new(20, &token, "sandboxes", &["default", "env=prod"])
            .unwrap()
            .object_cursor()
            .unwrap()
            .unwrap();
        assert_eq!(next.id, cursor.id);
        assert_eq!(next.created_at_ms, cursor.created_at_ms);
    }

    #[test]
    fn token_rejects_method_filter_and_cursor_mismatches() {
        let page = Pagination::new(10, "", "sandboxes", &["default"]).unwrap();
        let token = page.next_profile_token(Some("profile"));

        assert!(Pagination::new(10, &token, "providers", &["default"]).is_err());
        assert!(Pagination::new(10, &token, "sandboxes", &["other"]).is_err());
        assert!(
            Pagination::new(10, &token, "sandboxes", &["default"])
                .unwrap()
                .object_cursor()
                .is_err()
        );
    }

    #[test]
    fn token_rejects_malformed_and_unsupported_versions() {
        let malformed = Pagination::new(10, "not+base64", "sandboxes", &["default"])
            .expect_err("malformed tokens must be rejected");
        assert_eq!(malformed.code(), tonic::Code::InvalidArgument);

        let unsupported = URL_SAFE_NO_PAD.encode(
            PageToken {
                version: TOKEN_VERSION + 1,
                method: "sandboxes".to_string(),
                request_fingerprint: fingerprint(&["default"]),
                cursor: Some(Cursor::Profile(ProfileCursor {
                    key: "profile".to_string(),
                })),
            }
            .encode_to_vec(),
        );
        let error = Pagination::new(10, &unsupported, "sandboxes", &["default"])
            .expect_err("unsupported token versions must be rejected");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
