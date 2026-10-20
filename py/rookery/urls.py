# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Just enough of the WHATWG URL parser for http(s) URLs, so origin, href and
path comparisons match what the TypeScript rookery's `new URL()` produced."""

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

_DEFAULT_PORTS = {"http:": "80", "https:": "443", "ws:": "80", "wss:": "443"}


@dataclass
class Url:
    protocol: str  # "https:"
    hostname: str  # lowercased; IPv6 keeps its brackets
    port: str  # "" for the scheme default
    pathname: str
    search: str  # "" or "?..."
    hash: str  # "" or "#..."
    username: str = ""
    password: str = ""

    @property
    def host(self) -> str:
        return f"{self.hostname}:{self.port}" if self.port else self.hostname

    @property
    def origin(self) -> str:
        return f"{self.protocol}//{self.host}"

    @property
    def href(self) -> str:
        auth = ""
        if self.username or self.password:
            auth = self.username + (f":{self.password}" if self.password else "") + "@"
        return f"{self.protocol}//{auth}{self.host}{self.pathname}{self.search}{self.hash}"

    def param(self, name: str) -> str | None:
        for key, value in parse_qsl(self.search[1:], keep_blank_values=True):
            if key == name:
                return value
        return None

    def params(self) -> list[tuple[str, str]]:
        return parse_qsl(self.search[1:], keep_blank_values=True)


def parse_url(text: str) -> Url:
    """Raises ValueError where `new URL(text)` would throw."""
    if not isinstance(text, str):
        raise ValueError("not a URL")
    text = text.strip()
    parts = urlsplit(text)
    if not parts.scheme:
        raise ValueError("not a URL")
    protocol = parts.scheme.lower() + ":"
    special = protocol in _DEFAULT_PORTS or protocol == "file:"
    if special and protocol != "file:" and not parts.hostname:
        raise ValueError("not a URL")
    hostname = (parts.hostname or "").lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    port_text = "" if port is None or str(port) == _DEFAULT_PORTS.get(protocol) else str(port)
    pathname = parts.path or ("/" if special else "")
    query = "?" + parts.query if parts.query else ""
    fragment = "#" + parts.fragment if parts.fragment else ""
    return Url(protocol, hostname, port_text, pathname, query, fragment, parts.username or "", parts.password or "")


def is_url(text: str) -> bool:
    try:
        parse_url(text)
        return True
    except ValueError:
        return False
