#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Apply initial workflow labels to a newly opened GitHub issue."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAINTAINER_PERMISSIONS = {"admin", "maintain", "write"}


class GitHubAPI:
    def __init__(
        self, repository: str, token: str, api_url: str = "https://api.github.com"
    ):
        self.base = f"{api_url.rstrip('/')}/repos/{repository}"
        self.token = token

    def request(self, method: str, path: str, payload: dict | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.base}/{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def get_permission(self, login: str) -> str | None:
        login = urllib.parse.quote(login, safe="")
        try:
            return self.request("GET", f"collaborators/{login}/permission")[
                "permission"
            ]
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def get_labels(self, number: int) -> list[str]:
        return [
            label["name"] for label in self.request("GET", f"issues/{number}")["labels"]
        ]

    def add_labels(self, number: int, labels: list[str]) -> None:
        self.request("POST", f"issues/{number}/labels", {"labels": labels})


def apply_intake(api: GitHubAPI, number: int, author: str) -> list[str]:
    permission = api.get_permission(author)
    maintainer = permission in MAINTAINER_PERMISSIONS
    existing = api.get_labels(number)
    wanted = ("state:accepted",) if maintainer else ("state:new",)
    missing = [
        label
        for label in wanted
        if not any(
            current.startswith(label.split(":", 1)[0] + ":") for current in existing
        )
    ]
    if missing:
        api.add_labels(number, missing)
    return missing


def main() -> None:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if "pull_request" in event or event.get("action") != "opened":
        raise ValueError("expected an issues.opened event")
    api = GitHubAPI(
        os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_TOKEN"],
        os.getenv("GITHUB_API_URL", "https://api.github.com"),
    )
    number = int(event["issue"]["number"])
    added = apply_intake(api, number, event["issue"]["user"]["login"])
    print(f"Issue #{number}: added {', '.join(added) if added else 'no labels'}")


if __name__ == "__main__":
    main()
