#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Send a private triage assessment to the OpenShell duty engineer in Slack."""

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

ISSUE_URL = re.compile(r"https://github\.com/NVIDIA/OpenShell/issues/([1-9][0-9]*)\Z")


class SlackClient:
    def __init__(self, token: str):
        self.token = token

    def request(self, method: str, payload: dict):
        body = json.dumps(payload).encode() if method == "chat.postMessage" else None
        query = "" if body is not None else "?" + urllib.parse.urlencode(payload)
        request = urllib.request.Request(
            f"https://slack.com/api/{method}{query}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
        if not result.get("ok"):
            raise RuntimeError(
                f"Slack {method} failed: {result.get('error', 'unknown error')}"
            )
        return result

    def messages(self, channel: str, thread_ts: str | None = None) -> list[dict]:
        method = "conversations.replies" if thread_ts else "conversations.history"
        messages = []
        cursor = None
        while True:
            payload = {"channel": channel, "limit": 200}
            if thread_ts:
                payload["ts"] = thread_ts
            if cursor:
                payload["cursor"] = cursor
            page = self.request(method, payload)
            messages.extend(page.get("messages", []))
            cursor = page.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                return messages

    def post(self, channel: str, text: str, thread_ts: str | None = None) -> str:
        payload = {
            "channel": channel,
            "text": text,
            "unfurl_links": False,
            "unfurl_media": False,
        }
        if thread_ts:
            payload["thread_ts"] = thread_ts
        return self.request("chat.postMessage", payload)["ts"]


def deliver(
    slack: SlackClient,
    channel: str,
    duty_group: str,
    issue_url: str,
    summary: str,
    *,
    security: bool = False,
) -> bool:
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise ValueError("issue URL must identify an OpenShell GitHub issue")
    if not re.fullmatch(r"[CG][A-Z0-9]+", channel):
        raise ValueError("invalid Slack channel ID")
    if not re.fullmatch(r"S[A-Z0-9]+", duty_group):
        raise ValueError("invalid Slack user group ID")
    if security:
        summary = "Possible security report. Follow SECURITY.md and handle any sensitive details privately."
    elif not summary.strip():
        raise ValueError("triage summary is empty")
    elif len(summary) > 20_000:
        raise ValueError("triage summary exceeds 20,000 characters")

    number = match.group(1)
    marker = f"OpenShell triage issue #{number}"
    safe_summary = (
        summary.strip().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    digest = hashlib.sha256(safe_summary.encode()).hexdigest()[:16]
    text = f"<!subteam^{duty_group}> {marker}\n{issue_url}\n\n{safe_summary}\n\nAssessment: {digest}"

    roots = slack.messages(channel)
    root = next(
        (message for message in roots if marker in message.get("text", "")), None
    )
    if root:
        replies = slack.messages(channel, root["ts"])
        if any(
            f"Assessment: {digest}" in message.get("text", "")
            for message in [root, *replies]
        ):
            return False
        slack.post(channel, text, root["ts"])
    else:
        slack.post(channel, text)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue-url", required=True)
    parser.add_argument("--summary-file", type=Path)
    parser.add_argument("--security", action="store_true")
    args = parser.parse_args()
    if not args.security and args.summary_file is None:
        parser.error("--summary-file is required unless --security is set")
    summary = args.summary_file.read_text() if args.summary_file else ""
    posted = deliver(
        SlackClient(os.environ["OPENSHELL_TRIAGE_SLACK_BOT_TOKEN"]),
        os.getenv("OPENSHELL_TRIAGE_SLACK_CHANNEL_ID", "C0C20SDLDNW"),
        os.getenv("OPENSHELL_TRIAGE_SLACK_DUTY_GROUP_ID", "S0C099KM56F"),
        args.issue_url,
        summary,
        security=args.security,
    )
    print(
        "Triage handoff posted."
        if posted
        else "Identical triage handoff already posted."
    )


if __name__ == "__main__":
    main()
