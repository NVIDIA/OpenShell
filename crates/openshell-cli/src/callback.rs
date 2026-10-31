// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser-login callback listener binding.
//!
//! Both browser-based login flows (the OIDC Authorization Code + PKCE flow
//! and the edge/mTLS browser flow) receive their result on a short-lived
//! local HTTP server. By default that listener binds an ephemeral port on
//! IPv4 loopback (`127.0.0.1:0`), which is the safest option on a normal
//! host machine.
//!
//! When the CLI runs inside a container, a wrapper cannot know a randomly
//! chosen port in advance, so it cannot publish the port to the host and the
//! browser can never reach the callback. Two environment variables make the
//! flows container-friendly:
//!
//! - [`CALLBACK_PORT_ENV`] pins the listener to a fixed TCP port so the
//!   wrapper can publish `-p 127.0.0.1:<port>:<port>` before login starts.
//! - [`CALLBACK_BIND_ADDRESS_ENV`] overrides the bind address. Container
//!   runtimes with user-mode networking (pasta, slirp4netns) can only reach
//!   listeners bound to `0.0.0.0`, so a wrapper sets this to `0.0.0.0`
//!   inside the container while publishing the port to host loopback only.
//!   IPv6 addresses work too (for example `::1` or `::`): the browser-facing
//!   callback URL derives from the bound address (see [`callback_host`]), so
//!   an IPv6-bound listener directs the browser to `http://[::1]:<port>/...`
//!   instead of the unreachable `127.0.0.1`.
//!
//! Both variables default to unset, preserving the historical
//! `127.0.0.1:<ephemeral>` behavior. Binding `0.0.0.0` on a host machine
//! would expose the callback server to the local network, so it is never the
//! default and always requires the explicit variable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use miette::Result;
use tokio::net::TcpListener;

/// Environment variable pinning the browser-login callback listener to a
/// fixed TCP port (an integer from 1 to 65535).
pub(crate) const CALLBACK_PORT_ENV: &str = "OPENSHELL_CALLBACK_PORT";

/// Environment variable overriding the browser-login callback listener bind
/// address (an IP address; defaults to `127.0.0.1`).
pub(crate) const CALLBACK_BIND_ADDRESS_ENV: &str = "OPENSHELL_CALLBACK_BIND_ADDRESS";

/// Default callback listener bind address: IPv4 loopback.
const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Bind the TCP listener that receives browser-login callbacks.
///
/// Both browser login flows call this instead of binding a listener
/// directly. See the [module documentation][self] for the environment
/// variable controls and their security rationale.
pub(crate) async fn bind_callback_listener() -> Result<TcpListener> {
    let port = match std::env::var(CALLBACK_PORT_ENV) {
        Ok(raw) => Some(parse_callback_port(&raw)?),
        Err(_) => None,
    };

    let address = match std::env::var(CALLBACK_BIND_ADDRESS_ENV) {
        Ok(raw) => Some(parse_bind_address(&raw)?),
        Err(_) => None,
    };

    let addr = SocketAddr::new(address.unwrap_or(DEFAULT_BIND_ADDRESS), port.unwrap_or(0));

    TcpListener::bind(addr)
        .await
        .map_err(|e| bind_error(addr, e))
}

/// The IP address a browser uses to reach a bound callback listener.
///
/// Callback URLs target the bound address, except that wildcard binds are
/// reached through the matching loopback address: a listener on `0.0.0.0`
/// accepts `127.0.0.1` connections and a listener on `::` accepts `::1`
/// connections, so the browser is sent to the loopback literal of that
/// family (the container wrapper publishes the port to host loopback).
pub(crate) fn callback_target(local_addr: SocketAddr) -> IpAddr {
    match local_addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    }
}

/// The host a browser uses to reach a bound callback listener, in URL form.
///
/// IPv4 addresses render bare (`127.0.0.1`); IPv6 addresses are bracketed
/// (`[::1]`) as required by RFC 3986/RFC 8252. Use
/// [`callback_target`] for the unbracketed literal.
pub(crate) fn callback_host(local_addr: SocketAddr) -> String {
    match callback_target(local_addr) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Parse and validate [`CALLBACK_PORT_ENV`].
fn parse_callback_port(raw: &str) -> Result<u16> {
    let invalid = || {
        miette::miette!("{CALLBACK_PORT_ENV} must be an integer between 1 and 65535, got {raw:?}")
    };
    let port: u16 = raw.trim().parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    Ok(port)
}

/// Parse and validate [`CALLBACK_BIND_ADDRESS_ENV`].
fn parse_bind_address(raw: &str) -> Result<IpAddr> {
    raw.trim().parse().map_err(|_| {
        miette::miette!(
            "{CALLBACK_BIND_ADDRESS_ENV} must be an IP address \
             (e.g. 127.0.0.1, 0.0.0.0, or ::1), got {raw:?}"
        )
    })
}

/// Build a helpful error for a failed callback listener bind.
fn bind_error(addr: SocketAddr, source: std::io::Error) -> miette::Report {
    if addr.port() != 0 && source.kind() == std::io::ErrorKind::AddrInUse {
        miette::miette!(
            "browser-login callback port {} is already in use on {}.\n\
             Set {CALLBACK_PORT_ENV} to a free port, or unset it to let the \
             CLI pick an ephemeral port",
            addr.port(),
            addr.ip()
        )
    } else {
        miette::miette!("failed to bind browser-login callback listener on {addr}: {source}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Environment;

    /// Bind an ephemeral loopback listener, return its (now freed) port.
    async fn free_loopback_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
        listener.local_addr().expect("probe addr").port()
    }

    /// Read the fixed port under test back from the environment.
    ///
    /// The `Environment` harness re-enters the test in a child process with
    /// the variables applied, so the expected value is read from the
    /// environment rather than the parent's local variable.
    fn expected_fixed_port() -> u16 {
        std::env::var(CALLBACK_PORT_ENV)
            .expect("callback port env")
            .parse()
            .expect("callback port env parses")
    }

    #[test]
    fn invalid_callback_port_values_are_rejected() {
        for raw in ["", "0", "-1", "65536", "999999", "abc", "80.5", "8 0"] {
            let err = parse_callback_port(raw).expect_err(raw);
            let msg = format!("{err:#}");
            assert!(msg.contains(CALLBACK_PORT_ENV), "value {raw:?}: {msg}");
            assert!(msg.contains("between 1 and 65535"), "value {raw:?}: {msg}");
        }
    }

    #[test]
    fn valid_callback_port_values_are_accepted() {
        assert_eq!(parse_callback_port("1").unwrap(), 1);
        assert_eq!(parse_callback_port("8080").unwrap(), 8080);
        assert_eq!(parse_callback_port(" 8443 ").unwrap(), 8443);
        assert_eq!(parse_callback_port("65535").unwrap(), 65535);
    }

    #[test]
    fn invalid_bind_address_values_are_rejected() {
        for raw in ["", "   ", "banana", "localhost", "127.0.0.1:8080"] {
            let err = parse_bind_address(raw).expect_err(raw);
            let msg = format!("{err:#}");
            assert!(
                msg.contains(CALLBACK_BIND_ADDRESS_ENV),
                "value {raw:?}: {msg}"
            );
            assert!(msg.contains("IP address"), "value {raw:?}: {msg}");
        }
    }

    #[test]
    fn callback_host_maps_bindings_to_reachable_url_hosts() {
        let parse = |s: &str| -> SocketAddr { s.parse().expect("addr") };
        // Wildcard binds are reached through the matching loopback literal.
        assert_eq!(callback_host(parse("0.0.0.0:8080")), "127.0.0.1");
        assert_eq!(callback_host(parse("[::]:8080")), "[::1]");
        // Loopback binds keep their address; IPv6 renders bracketed.
        assert_eq!(callback_host(parse("127.0.0.1:8080")), "127.0.0.1");
        assert_eq!(callback_host(parse("[::1]:8080")), "[::1]");
        // Explicit specific addresses are addressed literally.
        assert_eq!(callback_host(parse("192.168.1.5:8080")), "192.168.1.5");
        assert_eq!(callback_host(parse("[2001:db8::5]:8080")), "[2001:db8::5]");
    }

    #[test]
    fn callback_target_maps_bindings_to_reachable_ips() {
        let parse = |s: &str| -> SocketAddr { s.parse().expect("addr") };
        assert_eq!(
            callback_target(parse("0.0.0.0:8080")),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            callback_target(parse("[::]:8080")),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            callback_target(parse("[2001:db8::5]:8080")),
            IpAddr::V6("2001:db8::5".parse::<Ipv6Addr>().expect("v6"))
        );
    }

    #[tokio::test]
    async fn ipv6_callback_is_reachable_at_advertised_host() {
        // Callback reachability: an IPv6-bound listener must be reachable at
        // exactly the host the browser flows advertise, and (on a host
        // without the address) must NOT be reachable via IPv4 loopback.
        Environment::new()
            .remove(CALLBACK_PORT_ENV)
            .set(CALLBACK_BIND_ADDRESS_ENV, "::1")
            .run_async(async {
                let listener = bind_callback_listener().await.expect("ipv6 bind");
                let addr = listener.local_addr().expect("local addr");
                let host = callback_host(addr);
                assert_eq!(host, "[::1]");

                let v6 = SocketAddr::new(
                    IpAddr::V6("::1".parse::<Ipv6Addr>().expect("v6")),
                    addr.port(),
                );
                let stream = tokio::net::TcpStream::connect(v6)
                    .await
                    .expect("[::1] callback must be reachable");
                drop(stream);

                let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
                let refused = tokio::net::TcpStream::connect(v4).await;
                assert!(refused.is_err(), "IPv4 loopback must not reach a ::1 bind");
            })
            .await;
    }

    #[test]
    fn busy_fixed_port_error_names_the_variable() {
        let addr: SocketAddr = "127.0.0.1:18080".parse().expect("parse addr");
        let err = bind_error(addr, std::io::Error::from(std::io::ErrorKind::AddrInUse));
        let msg = format!("{err:#}");
        assert!(msg.contains("already in use"), "message: {msg}");
        assert!(msg.contains("18080"), "message: {msg}");
        assert!(msg.contains(CALLBACK_PORT_ENV), "message: {msg}");
    }

    #[test]
    fn other_bind_errors_keep_the_listener_address() {
        let addr: SocketAddr = "127.0.0.1:18080".parse().expect("parse addr");
        let err = bind_error(
            addr,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        let msg = format!("{err:#}");
        assert!(msg.contains("127.0.0.1:18080"), "message: {msg}");
    }

    #[tokio::test]
    async fn binds_ephemeral_loopback_port_by_default() {
        Environment::new()
            .remove(CALLBACK_PORT_ENV)
            .remove(CALLBACK_BIND_ADDRESS_ENV)
            .run_async(async {
                let listener = bind_callback_listener().await.expect("default bind");
                let addr = listener.local_addr().expect("local addr");

                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_ne!(addr.port(), 0, "default bind must use an ephemeral port");
            })
            .await;
    }

    #[tokio::test]
    async fn binds_fixed_port_when_callback_port_is_set() {
        let port = free_loopback_port().await;
        Environment::new()
            .set(CALLBACK_PORT_ENV, port.to_string())
            .remove(CALLBACK_BIND_ADDRESS_ENV)
            .run_async(async {
                let expected = expected_fixed_port();
                let listener = bind_callback_listener().await.expect("fixed-port bind");
                let addr = listener.local_addr().expect("local addr");

                assert_eq!(addr.port(), expected);
                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            })
            .await;
    }

    #[tokio::test]
    async fn fixed_port_in_use_reports_clear_error() {
        let port = free_loopback_port().await;
        Environment::new()
            .set(CALLBACK_PORT_ENV, port.to_string())
            .remove(CALLBACK_BIND_ADDRESS_ENV)
            .run_async(async {
                let expected = expected_fixed_port();
                let _holder = TcpListener::bind(("127.0.0.1", expected))
                    .await
                    .expect("hold port");
                let err = bind_callback_listener()
                    .await
                    .expect_err("busy port must fail");
                let msg = format!("{err:#}");
                assert!(msg.contains("already in use"), "message: {msg}");
                assert!(msg.contains(CALLBACK_PORT_ENV), "message: {msg}");
            })
            .await;
    }

    #[tokio::test]
    async fn invalid_callback_port_env_fails_before_binding() {
        Environment::new()
            .set(CALLBACK_PORT_ENV, "not-a-port")
            .run_async(async {
                let err = bind_callback_listener()
                    .await
                    .expect_err("invalid port must fail");
                let msg = format!("{err:#}");
                assert!(msg.contains(CALLBACK_PORT_ENV), "message: {msg}");
                assert!(msg.contains("between 1 and 65535"), "message: {msg}");
            })
            .await;
    }

    #[tokio::test]
    async fn binds_all_interfaces_when_bind_address_is_set() {
        Environment::new()
            .remove(CALLBACK_PORT_ENV)
            .set(CALLBACK_BIND_ADDRESS_ENV, "0.0.0.0")
            .run_async(async {
                let listener = bind_callback_listener().await.expect("wildcard bind");
                let addr = listener.local_addr().expect("local addr");

                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_ne!(addr.port(), 0, "wildcard bind still uses ephemeral port");
            })
            .await;
    }

    #[tokio::test]
    async fn fixed_port_and_bind_address_combine() {
        let port = free_loopback_port().await;
        Environment::new()
            .set(CALLBACK_PORT_ENV, port.to_string())
            .set(CALLBACK_BIND_ADDRESS_ENV, "0.0.0.0")
            .run_async(async {
                let expected = expected_fixed_port();
                let listener = bind_callback_listener().await.expect("combined bind");
                let addr = listener.local_addr().expect("local addr");

                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_eq!(addr.port(), expected);
            })
            .await;
    }

    #[tokio::test]
    async fn ipv6_loopback_bind_address_is_supported() {
        Environment::new()
            .remove(CALLBACK_PORT_ENV)
            .set(CALLBACK_BIND_ADDRESS_ENV, "::1")
            .run_async(async {
                let listener = bind_callback_listener().await.expect("ipv6 bind");
                let addr = listener.local_addr().expect("local addr");

                assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
            })
            .await;
    }
}
