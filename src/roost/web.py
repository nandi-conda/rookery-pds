# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""A small request/response layer and router, shaped like the Hono app the
TypeScript rookery used (same default content types, CORS and 404)."""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

TEXT_PLAIN = "text/plain; charset=UTF-8"
TEXT_HTML = "text/html; charset=UTF-8"


class Headers:
    """Case-insensitive, single-valued request headers."""

    def __init__(self, pairs=()):
        self._values = {}
        for key, value in pairs:
            self._values[key.lower()] = value

    def get(self, name: str, default=None):
        return self._values.get(name.lower(), default)

    def items(self):
        return self._values.items()


class Request:
    def __init__(self, method: str, url: str, headers: Headers, body_reader=None, body: bytes | None = None,
                 raw=None):
        self.method = method.upper()
        self.url = url
        parts = urlsplit(url)
        self.path = parts.path or "/"
        self.search = f"?{parts.query}" if parts.query else ""
        self._query = parse_qsl(parts.query, keep_blank_values=True)
        self.headers = headers
        self._body_reader = body_reader
        self._body = body
        self.raw = raw  # the platform request, for passing through (websockets)
        self.params: dict[str, str] = {}

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def query(self, name: str) -> str | None:
        for key, value in self._query:
            if key == name:
                return value
        return None

    async def bytes(self) -> bytes:
        if self._body is None:
            self._body = await self._body_reader() if self._body_reader else b""
        return self._body

    async def json(self):
        """JSON.parse semantics: no NaN/Infinity, and integral numbers are integers."""
        return parse_json((await self.bytes()).decode("utf-8"))

    async def form(self) -> dict[str, str]:
        """Hono parseBody for urlencoded bodies (last value wins); {} for other types."""
        content_type = (self.header("content-type") or "").lower()
        if not content_type.startswith("application/x-www-form-urlencoded"):
            return {}
        return dict(parse_qsl((await self.bytes()).decode("utf-8"), keep_blank_values=True))

    async def oauth_params(self) -> dict[str, str]:
        """An OAuth endpoint body: urlencoded, or a JSON object of strings (as @atproto/oauth-client sends)."""
        content_type = (self.header("content-type") or "").lower()
        if not content_type.startswith("application/json"):
            return await self.form()
        body = await self.json()
        if not isinstance(body, dict) or not all(isinstance(value, str) for value in body.values()):
            raise ValueError("OAuth JSON body must be an object of strings")
        return body


def _reject_constant(name: str):
    raise ValueError(f"invalid JSON constant {name}")


def _js_number(text: str):
    value = float(text)
    return int(value) if value.is_integer() else value


def parse_json(text: str):
    return json.loads(text, parse_constant=_reject_constant, parse_float=_js_number)


def dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: list = field(default_factory=list)
    raw: object = None  # a platform response passed through untouched (websocket upgrade)

    def set_header(self, name: str, value: str) -> None:
        self.headers = [(key, val) for key, val in self.headers if key.lower() != name.lower()]
        self.headers.append((name, value))

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


def json_response(value, status: int = 200, headers: dict | None = None) -> Response:
    response = Response(status, dumps(value).encode("utf-8"), [("Content-Type", "application/json")])
    for key, val in (headers or {}).items():
        response.set_header(key, val)
    return response


def error(code: str, message: str, status: int) -> Response:
    return json_response({"error": code, "message": message}, status)


def text_response(text: str, status: int = 200, content_type: str = TEXT_PLAIN) -> Response:
    return Response(status, text.encode("utf-8"), [("Content-Type", content_type)])


def html_response(html: str, status: int = 200) -> Response:
    return text_response(html, status, TEXT_HTML)


def body_response(body: bytes = b"", status: int = 200, content_type: str | None = None) -> Response:
    return Response(status, body, [("Content-Type", content_type)] if content_type else [])


def redirect(location: str, status: int = 302) -> Response:
    return Response(status, b"", [("Location", location)])


def not_found() -> Response:
    return text_response("404 Not Found", 404)


class Router:
    def __init__(self):
        self.routes: list[tuple[str, re.Pattern, object]] = []

    def route(self, method: str, pattern: str):
        regex = re.compile("^" + re.sub(r":([a-zA-Z_]+)", r"(?P<\1>[^/]+)", pattern) + "$")

        def register(handler):
            self.routes.append((method, regex, handler))
            return handler
        return register

    def get(self, pattern):
        return self.route("GET", pattern)

    def post(self, pattern):
        return self.route("POST", pattern)

    def put(self, pattern):
        return self.route("PUT", pattern)

    def delete(self, pattern):
        return self.route("DELETE", pattern)

    def match(self, method: str, path: str):
        lookup = "GET" if method == "HEAD" else method
        for route_method, regex, handler in self.routes:
            if route_method != lookup:
                continue
            found = regex.match(path)
            if found:
                return handler, {key: unquote(value) for key, value in found.groupdict().items()}
        return None, {}
