# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The slice of RFC 8941 structured field values that HTTP message signatures and
space MAC headers need: dictionaries whose members are items or inner lists, with
parameters."""

import base64
import re

_KEY_RE = re.compile(r"[a-z*][a-z0-9_.*-]*")
_TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9:/!#$%&'*+.^_`|~-]*")
_NUMBER_RE = re.compile(r"-?\d{1,15}(\.\d{1,3})?")


class SfvError(ValueError):
    pass


class Token(str):
    pass


class _Parser:
    def __init__(self, text: str):
        self.text, self.pos = text, 0

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.pos += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.pos += 1

    def key(self) -> str:
        match = _KEY_RE.match(self.text, self.pos)
        if not match:
            raise SfvError("invalid key")
        self.pos = match.end()
        return match.group()

    def bare_item(self):
        char = self.peek()
        if char == '"':
            self.pos += 1
            out = []
            while True:
                char = self.peek()
                if not char:
                    raise SfvError("unterminated string")
                self.pos += 1
                if char == "\\":
                    escaped = self.peek()
                    if escaped not in ('"', "\\"):
                        raise SfvError("invalid escape")
                    out.append(escaped)
                    self.pos += 1
                elif char == '"':
                    return "".join(out)
                elif not (0x20 <= ord(char) <= 0x7E):
                    raise SfvError("invalid string character")
                else:
                    out.append(char)
        if char == ":":
            end = self.text.find(":", self.pos + 1)
            if end == -1:
                raise SfvError("unterminated byte sequence")
            raw = self.text[self.pos + 1:end]
            if not re.fullmatch(r"[A-Za-z0-9+/=]*", raw):
                raise SfvError("invalid byte sequence")
            self.pos = end + 1
            try:
                return base64.b64decode(raw + "=" * (-len(raw) % 4))
            except ValueError as exc:
                raise SfvError("invalid byte sequence") from exc
        if char == "?":
            value = self.text[self.pos + 1:self.pos + 2]
            if value not in ("0", "1"):
                raise SfvError("invalid boolean")
            self.pos += 2
            return value == "1"
        if char == "-" or char.isdigit():
            match = _NUMBER_RE.match(self.text, self.pos)
            if not match:
                raise SfvError("invalid number")
            self.pos = match.end()
            return float(match.group()) if match.group(1) else int(match.group())
        match = _TOKEN_RE.match(self.text, self.pos)
        if not match:
            raise SfvError("invalid item")
        self.pos = match.end()
        return Token(match.group())

    def params(self) -> dict:
        params = {}
        while self.peek() == ";":
            self.pos += 1
            self.skip_sp()
            name = self.key()
            value = True
            if self.peek() == "=":
                self.pos += 1
                value = self.bare_item()
            params[name] = value
        return params

    def member(self):
        if self.peek() == "(":
            self.pos += 1
            items = []
            while True:
                self.skip_sp()
                if self.peek() == ")":
                    self.pos += 1
                    return ("list", items, self.params())
                items.append((self.bare_item(), self.params()))
                if self.peek() not in (" ", ")"):
                    raise SfvError("invalid inner list")
        return ("item", self.bare_item(), self.params())


def parse_dictionary(text: str) -> dict:
    parser = _Parser(text)
    parser.skip_sp()
    out = {}
    while parser.peek():
        name = parser.key()
        if parser.peek() == "=":
            parser.pos += 1
            out[name] = parser.member()
        else:
            out[name] = ("item", True, parser.params())
        parser.skip_ows()
        if not parser.peek():
            break
        if parser.peek() != ",":
            raise SfvError("expected comma")
        parser.pos += 1
        parser.skip_ows()
        if not parser.peek():
            raise SfvError("trailing comma")
    return out


def _serialize_bare(value) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Token):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode() + ":"
    raise SfvError(f"cannot serialize {type(value).__name__}")


def _serialize_params(params: dict) -> str:
    return "".join(f";{name}" if value is True else f";{name}={_serialize_bare(value)}" for name, value in params.items())


def serialize_inner_list(items: list, params: dict) -> str:
    inner = " ".join(_serialize_bare(value) + _serialize_params(item_params) for value, item_params in items)
    return f"({inner}){_serialize_params(params)}"


def serialize_dictionary(members: dict) -> str:
    """A dictionary of bare items without parameters."""
    return ", ".join(f"{name}={_serialize_bare(value)}" for name, value in members.items())
