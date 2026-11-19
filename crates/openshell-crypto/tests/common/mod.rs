// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

#[cfg(feature = "openssl")]
use openshell_crypto::{CryptoContext, OpenSsl};
#[cfg(feature = "openssl")]
use std::sync::Once;

// The context-selection test uses only the backend-neutral handshake helper.
#[cfg(feature = "openssl")]
#[allow(dead_code)]
pub fn init_openssl() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Explicit facade selection must override an existing Rustls default.
        #[cfg(feature = "aws-lc")]
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
        openshell_crypto::install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap();
    });
}

pub fn handshake(
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
    host: &'static str,
) -> Result<(rustls::ClientConnection, rustls::ServerConnection), rustls::Error> {
    let mut client = rustls::ClientConnection::new(Arc::new(client), host.try_into().unwrap())?;
    let mut server = rustls::ServerConnection::new(Arc::new(server))?;
    for _ in 0..10 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    Err(rustls::Error::General("handshake did not finish".into()))
}
