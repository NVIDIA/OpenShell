# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from openai import OpenAI

client = OpenAI(api_key="dummy")

response = client.chat.completions.create(
    model="router",
    messages=[{"role": "user", "content": "Reply with exactly: NAV_OK"}],
    temperature=0,
)

content = (response.choices[0].message.content or "").strip()
print(f"model={response.model}")
print(f"content={content}")
