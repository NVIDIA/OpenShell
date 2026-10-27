// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::proto::ServiceRouteSnapshot;
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

const MAX_ROUTES: usize = 4096;
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_LEASE: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct Route {
    pub endpoint: SocketAddr,
    pub version: String,
    pub deadline: Instant,
    pub connections: Arc<Semaphore>,
}

pub type Routes = BTreeMap<String, Route>;
pub type RouteCache = watch::Sender<Routes>;

pub fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn valid_workspace(name: &str) -> bool {
    valid_hostname(name) && name.len() <= 19 && !name.contains('.')
}

#[cfg(test)]
fn replace(
    cache: &RouteCache,
    snapshot: ServiceRouteSnapshot,
    workspace: &str,
) -> Result<(), &'static str> {
    replace_selected(cache, snapshot, &[workspace.to_string()], false)
}

/// A complete view is validated before replacement. Receipt never extends a
/// gateway's absolute expiry; a monotonic deadline prevents local clock rollback.
pub fn replace_selected(
    cache: &RouteCache,
    snapshot: ServiceRouteSnapshot,
    workspaces: &[String],
    all_workspaces: bool,
) -> Result<(), &'static str> {
    if snapshot.routes.len() > MAX_ROUTES || snapshot.revision.is_empty() {
        return Err("invalid snapshot bounds or revision");
    }
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "invalid system clock")?
            .as_millis(),
    )
    .map_err(|_| "invalid system clock")?;
    let now = Instant::now();
    let old = cache.borrow();
    let mut next = Routes::new();
    let mut metadata_bytes = snapshot.revision.len();
    for route in snapshot.routes {
        metadata_bytes = metadata_bytes
            .saturating_add(route.hostname.len())
            .saturating_add(route.installation_version.len())
            .saturating_add(route.workspace.len())
            .saturating_add(route.sandbox.len())
            .saturating_add(route.name.len());
        if metadata_bytes > MAX_METADATA_BYTES
            || !valid_workspace(&route.workspace)
            || (!all_workspaces && !workspaces.contains(&route.workspace))
            || !valid_hostname(&route.hostname)
            || route.installation_version.is_empty()
        {
            return Err("invalid discovered route identity");
        }
        let endpoint = route.endpoint.ok_or("missing supervisor endpoint")?;
        let host: IpAddr = endpoint.host.parse().map_err(|_| "invalid supervisor IP")?;
        let port = u16::try_from(endpoint.port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or("invalid supervisor port")?;
        let expiry = route
            .expires_at
            .as_ref()
            .and_then(|value| openshell_core::time::timestamp_to_millis(value).ok())
            .ok_or("invalid installation expiry")?;
        let remaining = expiry.saturating_sub(now_ms);
        if remaining <= 0 {
            continue;
        }
        let deadline = now + Duration::from_millis(remaining.unsigned_abs()).min(MAX_LEASE);
        let connections = old.get(&route.hostname).map_or_else(
            || Arc::new(Semaphore::new(64)),
            |previous| previous.connections.clone(),
        );
        if next
            .insert(
                route.hostname,
                Route {
                    endpoint: SocketAddr::new(host, port),
                    version: route.installation_version,
                    deadline,
                    connections,
                },
            )
            .is_some()
        {
            return Err("duplicate discovered hostname");
        }
    }
    drop(old);
    cache.send_replace(next);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{DiscoveredServiceRoute, ServiceRouteEndpoint};

    fn snapshot() -> ServiceRouteSnapshot {
        let now = openshell_core::time::timestamp_from_millis(crate::now_ms() + 10_000).unwrap();
        ServiceRouteSnapshot {
            revision: "revision".into(),
            routes: vec![DiscoveredServiceRoute {
                workspace: "default".into(),
                sandbox: "demo".into(),
                name: "web".into(),
                hostname: "demo.example.com".into(),
                installation_version: "owner-1".into(),
                endpoint: Some(ServiceRouteEndpoint {
                    host: "127.0.0.1".into(),
                    port: 9443,
                }),
                expires_at: Some(now),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn renewal_preserves_capacity_and_errors_do_not_publish_partial_views() {
        let (cache, _) = watch::channel(Routes::new());
        replace(&cache, snapshot(), "default").unwrap();
        let connections = cache.borrow()["demo.example.com"].connections.clone();
        replace(&cache, snapshot(), "default").unwrap();
        assert!(Arc::ptr_eq(
            &connections,
            &cache.borrow()["demo.example.com"].connections
        ));
        let mut duplicate = snapshot();
        duplicate.routes.push(duplicate.routes[0].clone());
        assert!(replace(&cache, duplicate, "default").is_err());
        assert_eq!(cache.borrow().len(), 1);
        assert!(replace(&cache, snapshot(), "other").is_err());
        let mut expired = snapshot();
        expired.routes[0].expires_at =
            openshell_core::time::timestamp_from_millis(crate::now_ms() - 1).ok();
        replace(&cache, expired, "default").unwrap();
        assert!(cache.borrow().is_empty());
    }
    #[test]
    fn combined_views_validate_every_workspace_before_atomic_replacement() {
        let (cache, _) = watch::channel(Routes::new());
        let mut view = snapshot();
        let mut other = view.routes[0].clone();
        other.workspace = "team-b".into();
        other.hostname = "team-b.example.com".into();
        view.routes.push(other);
        let scopes = vec!["default".to_string(), "team-b".to_string()];
        replace_selected(&cache, view.clone(), &scopes, false).unwrap();
        assert_eq!(cache.borrow().len(), 2);
        let previous = cache.borrow()["team-b.example.com"].connections.clone();
        replace_selected(&cache, view.clone(), &[], true).unwrap();
        assert!(Arc::ptr_eq(
            &previous,
            &cache.borrow()["team-b.example.com"].connections
        ));
        view.routes[1].workspace = "outside".into();
        assert!(replace_selected(&cache, view, &scopes, false).is_err());
        assert_eq!(cache.borrow().len(), 2);
        let empty = ServiceRouteSnapshot {
            revision: "empty".into(),
            routes: vec![],
        };
        replace_selected(&cache, empty, &[], true).unwrap();
        assert!(cache.borrow().is_empty());
    }
}
