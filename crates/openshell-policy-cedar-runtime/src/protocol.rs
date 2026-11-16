// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// The proxy's protocol for an endpoint Cedar inspects with `protocol`.
///
/// `websocket-graphql` is a `websocket` endpoint; whether the relay applies
/// GraphQL message policy is carried separately (see
/// [`openshell_policy_cedar::L7Protocol::websocket_graphql_messages`]).
pub fn l7_protocol(
    protocol: openshell_policy_cedar::L7Protocol,
) -> openshell_core::policy_l7::L7Protocol {
    use openshell_core::policy_l7::L7Protocol;
    use openshell_policy_cedar::L7Protocol as Cedar;
    match protocol {
        Cedar::Rest => L7Protocol::Rest,
        Cedar::JsonRpc => L7Protocol::JsonRpc,
        Cedar::Mcp => L7Protocol::Mcp,
        Cedar::Graphql => L7Protocol::Graphql,
        Cedar::Websocket | Cedar::WebsocketGraphql => L7Protocol::Websocket,
    }
}

#[cfg(test)]
mod tests {
    use openshell_core::policy_l7::L7Protocol;
    use openshell_policy_cedar::L7Protocol as Cedar;

    #[test]
    fn every_cedar_protocol_converts_to_the_config_protocol_of_its_label() {
        // Fails to compile when a protocol is added, so it gets a row below.
        let _ = |protocol: Cedar| match protocol {
            Cedar::Rest
            | Cedar::JsonRpc
            | Cedar::Mcp
            | Cedar::Graphql
            | Cedar::Websocket
            | Cedar::WebsocketGraphql => {}
        };
        for (cedar, expected) in [
            (Cedar::Rest, L7Protocol::Rest),
            (Cedar::JsonRpc, L7Protocol::JsonRpc),
            (Cedar::Mcp, L7Protocol::Mcp),
            (Cedar::Graphql, L7Protocol::Graphql),
            (Cedar::Websocket, L7Protocol::Websocket),
            (Cedar::WebsocketGraphql, L7Protocol::Websocket),
        ] {
            assert_eq!(super::l7_protocol(cedar), expected, "{cedar}");
            // The same protocol the proxy's config parser reads from the label.
            assert_eq!(
                L7Protocol::parse(cedar.config_label()),
                Some(expected),
                "{cedar}"
            );
        }
    }
}
