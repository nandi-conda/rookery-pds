# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Outbound HTTP as the app sees it: `await env.http.fetch(...) -> HttpResponse`.

The Worker implements fetch with the runtime's fetch; tests pass a fake.
"""

import json
from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    status: int
    body: bytes = b""
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.body)
