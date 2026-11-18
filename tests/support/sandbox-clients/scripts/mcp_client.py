# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs an MCP client against the fixture at HOST:PORT for each revision in the
# JSON list VERSIONS: discovery or initialization, an allowed and a denied
# tool, and for the sessionless revision, a subscription. Prints
# `MCP_OK version=<version>` after each revision's checks pass.
import json
import sys
import urllib.error
import urllib.request

HOST = sys.argv[1]
PORT = int(sys.argv[2])
VERSIONS = json.loads(sys.argv[3])
SESSIONLESS = "2026-07-28"

# Direct client connections pass through the sandbox's transparent interception.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post(request_id, method, params, version):
    params = dict(params)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if method != "initialize":
        headers["MCP-Protocol-Version"] = version
    if version == SESSIONLESS:
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "openshell-e2e", "version": "1"},
        }
        headers["Mcp-Method"] = method
        if method == "tools/call":
            headers["Mcp-Name"] = params["name"]
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        message["id"] = request_id
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/mcp",
        data=json.dumps(message).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.headers.get_content_type(), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get_content_type(), error.read()


expected_receipts = []
for version in VERSIONS:
    if version == SESSIONLESS:
        status, content_type, body = post(1, "server/discover", {}, version)
        assert status == 200, (version, "discovery", status, body)
        assert content_type == "application/json", (version, content_type)
        discovery = json.loads(body)
        assert discovery["id"] == 1, discovery
        assert discovery["result"]["supportedVersions"] == [version], discovery
        expected_receipts.append([version, "server/discover", None])
    else:
        status, _, body = post(1, "initialize", {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "openshell-e2e", "version": "1"},
        }, version)
        assert status == 200, (version, "initialize", status, body)
        assert json.loads(body)["result"]["protocolVersion"] == version, body
        expected_receipts.append([version, "initialize", None])
        status, _, body = post(None, "notifications/initialized", {}, version)
        assert status == 202, (version, "initialized", status, body)
        expected_receipts.append([version, "notifications/initialized", None])

    status, _, body = post(2, "tools/call", {"name": "read_status", "arguments": {}}, version)
    assert status == 200, (version, "allowed tool", status, body)
    tool = json.loads(body)
    assert tool["id"] == 2, tool
    assert tool["result"]["content"] == [{"type": "text", "text": "read_status"}], tool
    expected_receipts.append([version, "tools/call", "read_status"])
    assert tool["result"]["_meta"]["fixtureRequests"] == expected_receipts, tool

    status, _, body = post(3, "tools/call", {"name": "read_details", "arguments": {}}, version)
    assert status == 403, (version, "denied tool", status, body)

    # The fixture accepts both tools. A later allowed call proves the denial
    # came from the proxy and no denied operation reached the upstream.
    status, _, body = post(4, "tools/call", {"name": "read_status", "arguments": {}}, version)
    assert status == 200, (version, "receipt tool", status, body)
    receipt = json.loads(body)
    assert receipt["id"] == 4, receipt
    expected_receipts.append([version, "tools/call", "read_status"])
    assert receipt["result"]["_meta"]["fixtureRequests"] == expected_receipts, receipt

    if version == SESSIONLESS:
        status, content_type, body = post(
            5, "subscriptions/listen", {"notifications": {"toolsListChanged": True}}, version
        )
        assert status == 200, (version, "subscription", status, body)
        assert content_type == "text/event-stream", (content_type, body)
        events = [json.loads(line[6:]) for line in body.decode().splitlines() if line.startswith("data: ")]
        assert len(events) == 3, events
        assert events[0]["method"] == "notifications/subscriptions/acknowledged", events
        assert events[0]["params"]["notifications"] == {"toolsListChanged": True}, events
        assert events[1]["method"] == "notifications/tools/list_changed", events
        assert events[1]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == 5, events
        assert events[2]["id"] == 5 and events[2]["result"]["resultType"] == "complete", events
        expected_receipts.append([version, "subscriptions/listen", None])

    print(f"MCP_OK version={version}", flush=True)
