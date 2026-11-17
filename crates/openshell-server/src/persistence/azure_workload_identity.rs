// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Explicit AKS federation and credential-aware `PostgreSQL` pool acquisitions.
//!
//! `SQLx` 0.9 has no before-connect callback. This adapter keeps `min_connections`
//! at zero and installs a sufficiently long-lived credential before entering a
//! bounded `SQLx` acquisition. Thus every physical connection attempt sees a valid
//! credential, including `SQLx`'s internal retries. Idle sessions do not need a
//! new credential and remain usable during an identity-service outage.

use futures::TryStreamExt;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use serde::Deserialize;
use sqlx::pool::{MaybePoolConnection, PoolConnection};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode, PgStatement, PgTypeInfo};
use sqlx::{Acquire, Connection, Either, Execute, Executor, PgPool, Postgres, Transaction};
use sqlx_core::sql_str::SqlStr;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::time::Instant;

const POSTGRES_SCOPE: &str = "https://ossrdbms-aad.database.windows.net/.default";
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const CLOCK_SKEW: Duration = Duration::from_secs(30);
// SQLx exposes no notification for returned idle connections. Poll only while
// refresh is unavailable/in flight; a valid cached token keeps SQLx's native wait.
const REUSE_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn config_error(message: &'static str) -> sqlx::Error {
    sqlx::Error::Configuration(message.into())
}

fn unavailable(message: &'static str) -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// Deliberately has no `DefaultAzureCredential` chain or configurable scope.
pub(super) struct AzureWorkloadIdentity {
    client_id: String,
    token_file: PathBuf,
    endpoint: String,
    client: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for AzureWorkloadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AzureWorkloadIdentity { credentials: [REDACTED] }")
    }
}

impl AzureWorkloadIdentity {
    pub(super) fn from_env() -> Result<Arc<Self>, sqlx::Error> {
        let tenant = std::env::var("AZURE_TENANT_ID")
            .map_err(|_| config_error("Azure database authentication requires AZURE_TENANT_ID"))?;
        let client_id = std::env::var("AZURE_CLIENT_ID")
            .map_err(|_| config_error("Azure database authentication requires AZURE_CLIENT_ID"))?;
        if uuid::Uuid::parse_str(&tenant).is_err() || uuid::Uuid::parse_str(&client_id).is_err() {
            return Err(config_error(
                "AZURE_TENANT_ID and AZURE_CLIENT_ID must be UUIDs",
            ));
        }
        let authority = std::env::var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|_| "https://login.microsoftonline.com/".into());
        if authority.trim_end_matches('/') != "https://login.microsoftonline.com" {
            return Err(config_error(
                "Azure database authentication requires the public-cloud AZURE_AUTHORITY_HOST https://login.microsoftonline.com/",
            ));
        }
        let token_file =
            PathBuf::from(std::env::var("AZURE_FEDERATED_TOKEN_FILE").map_err(|_| {
                config_error("Azure database authentication requires AZURE_FEDERATED_TOKEN_FILE")
            })?);
        if !token_file.is_absolute() {
            return Err(config_error(
                "AZURE_FEDERATED_TOKEN_FILE must be an absolute file path",
            ));
        }
        openshell_crypto::tls::ensure_default_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| {
                config_error("could not initialize Azure database identity HTTP client")
            })?;
        Ok(Arc::new(Self {
            client_id,
            token_file,
            endpoint: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
            client,
            token: Mutex::new(None),
        }))
    }

    fn cached_access_token(&self, connection_budget: Duration) -> Option<String> {
        let cached = self.token.try_lock().ok()?;
        cached
            .as_ref()
            .filter(|token| token.expires_at > Instant::now() + connection_budget + CLOCK_SKEW)
            .map(|token| token.value.clone())
    }

    async fn access_token(&self, connection_budget: Duration) -> Result<String, sqlx::Error> {
        // One refresh per replica, shared by data and advisory-lock pools.
        let mut cached = self.token.lock().await;
        let minimum = connection_budget + CLOCK_SKEW;
        if let Some(token) = &*cached
            && token.expires_at > Instant::now() + minimum
        {
            return Ok(token.value.clone());
        }
        // AKS updates this symlink atomically. Reopen it for every refresh;
        // retaining a file descriptor would pin the previous projected token.
        let mut file = tokio::fs::File::open(&self.token_file).await.map_err(|_| {
            unavailable("cannot read AZURE_FEDERATED_TOKEN_FILE; check the gateway ServiceAccount and workload identity projection")
        })?;
        if !file
            .metadata()
            .await
            .map_err(|_| unavailable("cannot inspect Azure projected identity token"))?
            .is_file()
        {
            return Err(config_error(
                "AZURE_FEDERATED_TOKEN_FILE must reference a regular file",
            ));
        }
        let mut assertion = String::new();
        (&mut file)
            .take((MAX_CREDENTIAL_BYTES + 1) as u64)
            .read_to_string(&mut assertion)
            .await
            .map_err(|_| unavailable("cannot read Azure projected identity token"))?;
        let assertion = assertion.trim();
        if assertion.is_empty() || assertion.len() > MAX_CREDENTIAL_BYTES {
            return Err(config_error(
                "Azure projected identity token is empty or exceeds 64 KiB",
            ));
        }
        let started = Instant::now();
        let mut response = self
            .client
            .post(&self.endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion),
                ("scope", POSTGRES_SCOPE),
            ])
            .send()
            .await
            .map_err(|_| {
                unavailable("Azure database token exchange unavailable; check Entra connectivity")
            })?;
        if !response.status().is_success() {
            // Never display an upstream error body: it may echo an assertion.
            return Err(unavailable(
                "Azure database token exchange rejected; check tenant, client ID, and the ServiceAccount federated credential",
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| unavailable("Azure database token response could not be read"))?
        {
            if body.len() + chunk.len() > MAX_CREDENTIAL_BYTES {
                return Err(unavailable("Azure database token response exceeds 64 KiB"));
            }
            body.extend_from_slice(&chunk);
        }
        let response: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| unavailable("Azure database token response is invalid"))?;
        if response.access_token.is_empty()
            || response.access_token.len() > MAX_CREDENTIAL_BYTES
            || response.access_token.chars().any(char::is_whitespace)
            || !response.token_type.eq_ignore_ascii_case("Bearer")
            || response.expires_in > 7 * 24 * 3600
        {
            return Err(unavailable(
                "Azure database token response has invalid credential metadata",
            ));
        }
        let expires_at = started + Duration::from_secs(response.expires_in);
        if expires_at <= Instant::now() + minimum {
            return Err(unavailable(
                "Azure database token expires before a connection can safely complete",
            ));
        }
        let value = response.access_token;
        *cached = Some(CachedToken {
            value: value.clone(),
            expires_at,
        });
        Ok(value)
    }
}

pub(super) fn validate_url(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    let parsed = url::Url::parse(url)
        .map_err(|_| config_error("Azure database authentication requires a PostgreSQL URL"))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed
            .query_pairs()
            .any(|(key, _)| matches!(key.as_ref(), "password" | "passfile" | "host" | "hostaddr"))
    {
        return Err(config_error(
            "Azure database authentication requires an explicit PostgreSQL host/user and a password-free URL without host overrides or passfile",
        ));
    }
    let options: PgConnectOptions = url
        .parse()
        .map_err(|_| config_error("Azure database connection options are invalid"))?;
    if !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        return Err(config_error(
            "Azure database authentication requires sslmode=verify-full",
        ));
    }
    // Overwrite SQLx's ambient PGPASSWORD/.pgpass even before the first token.
    Ok(options.password(""))
}

/// All access to the underlying pool stays here: no caller can bypass refresh.
#[derive(Clone)]
pub(super) struct CredentialPool {
    inner: PgPool,
    identity: Option<Arc<AzureWorkloadIdentity>>,
}

impl fmt::Debug for CredentialPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialPool")
            .field("azure", &self.identity.is_some())
            .finish_non_exhaustive()
    }
}

impl From<PgPool> for CredentialPool {
    fn from(inner: PgPool) -> Self {
        Self {
            inner,
            identity: None,
        }
    }
}

impl CredentialPool {
    pub(super) fn azure(
        options: PgPoolOptions,
        connect: PgConnectOptions,
        identity: Arc<AzureWorkloadIdentity>,
    ) -> Self {
        Self {
            // Maintenance must not open a connection behind the credential guard.
            inner: options
                .min_connections(0)
                .max_lifetime(None)
                .connect_lazy_with(connect),
            identity: Some(identity),
        }
    }

    pub(super) fn acquire(&self) -> BoxFuture<'_, Result<PoolConnection<Postgres>, sqlx::Error>> {
        Box::pin(async move {
            let Some(identity) = &self.identity else {
                return self.inner.acquire().await;
            };
            let budget = self.inner.options().get_acquire_timeout();
            let mut refresh_error = None;
            let acquired = tokio::time::timeout(budget, async {
                if let Some(connection) = self.try_reuse().await? {
                    return Ok(connection);
                }
                let reusable = async {
                    loop {
                        if let Some(connection) = self.try_reuse().await? {
                            return Ok(connection);
                        }
                        tokio::time::sleep(REUSE_POLL_INTERVAL).await;
                    }
                };
                tokio::pin!(reusable);
                let opening = async {
                    let token = loop {
                        // Preserve SQLx's native queuing when credentials are
                        // cached, including when every connection is checked out.
                        if let Some(token) = identity.cached_access_token(budget) {
                            break token;
                        }
                        // At capacity, only a returned session can serve us.
                        // Do not make healthy busy sessions depend on Entra.
                        if self.inner.size() < self.inner.options().get_max_connections() {
                            break identity.access_token(budget).await?;
                        }
                        tokio::time::sleep(REUSE_POLL_INTERVAL).await;
                    };
                    let options = (*self.inner.connect_options()).clone().password(&token);
                    self.inner.set_connect_options(options);
                    self.inner.acquire().await
                };
                tokio::select! {
                    biased;
                    result = &mut reusable => result,
                    result = opening => match result {
                        Ok(connection) => Ok(connection),
                        Err(error) if self.inner.size() == 0 => Err(error),
                        Err(error) => {
                            // A failed refresh must not preempt an existing
                            // healthy session that can return before the deadline.
                            refresh_error = Some(error);
                            reusable.await
                        }
                    },
                }
            })
            .await;
            acquired.unwrap_or_else(|_| Err(refresh_error.unwrap_or_else(|| unavailable(
                "Azure database connection acquisition timed out; check workload identity and PostgreSQL connectivity",
            ))))
        })
    }

    async fn try_reuse(&self) -> Result<Option<PoolConnection<Postgres>>, sqlx::Error> {
        if self.inner.is_closed() {
            return Err(sqlx::Error::PoolClosed);
        }
        if let Some(mut connection) = self.inner.try_acquire() {
            if connection.ping().await.is_ok() {
                return Ok(Some(connection));
            }
            let _ = connection.close().await;
        }
        Ok(None)
    }

    pub(super) async fn begin(&self) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        Transaction::begin(
            MaybePoolConnection::PoolConnection(self.acquire().await?),
            None,
        )
        .await
    }
    pub(super) fn options(&self) -> &PgPoolOptions {
        self.inner.options()
    }
    #[cfg(test)]
    pub(super) fn size(&self) -> u32 {
        self.inner.size()
    }
    #[cfg(test)]
    pub(super) fn num_idle(&self) -> usize {
        self.inner.num_idle()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(super) async fn close(&self) {
        self.inner.close().await;
    }
}

impl<'a> Acquire<'a> for &'a CredentialPool {
    type Database = Postgres;
    type Connection = PoolConnection<Postgres>;
    fn acquire(self) -> BoxFuture<'a, Result<Self::Connection, sqlx::Error>> {
        CredentialPool::acquire(self)
    }
    fn begin(self) -> BoxFuture<'a, Result<Transaction<'a, Postgres>, sqlx::Error>> {
        Box::pin(async move {
            Transaction::begin(
                MaybePoolConnection::PoolConnection(self.acquire().await?),
                None,
            )
            .await
        })
    }
}

impl<'p> Executor<'p> for &CredentialPool {
    type Database = Postgres;

    fn fetch_many<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxStream<'e, Result<Either<sqlx::postgres::PgQueryResult, PgRow>, sqlx::Error>>
    where
        E: 'q + Execute<'q, Postgres>,
    {
        let pool = self.clone();
        Box::pin(async_stream::try_stream! {
            let mut connection = pool.acquire().await?;
            let mut rows = connection.fetch_many(query);
            while let Some(row) = rows.try_next().await? { yield row; }
        })
    }

    fn fetch_optional<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Option<PgRow>, sqlx::Error>>
    where
        E: 'q + Execute<'q, Postgres>,
    {
        let pool = self.clone();
        Box::pin(async move { pool.acquire().await?.fetch_optional(query).await })
    }

    fn prepare_with<'e>(
        self,
        sql: SqlStr,
        parameters: &'e [PgTypeInfo],
    ) -> BoxFuture<'e, Result<PgStatement, sqlx::Error>>
    where
        'p: 'e,
    {
        let pool = self.clone();
        Box::pin(async move { pool.acquire().await?.prepare_with(sql, parameters).await })
    }

    fn describe<'e>(
        self,
        sql: SqlStr,
    ) -> BoxFuture<'e, Result<sqlx::Describe<Postgres>, sqlx::Error>> {
        let pool = self.clone();
        Box::pin(async move { pool.acquire().await?.describe(sql).await })
    }
}

#[cfg(test)]
#[path = "azure_workload_identity_tests.rs"]
mod tests;
