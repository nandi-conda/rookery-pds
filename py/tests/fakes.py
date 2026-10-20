# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""In-memory stand-ins for the Worker platform (D1, DO SQLite, R2, PLC, fetch)
so the app runs end to end in tests, Durable Object RPC boundary included."""

import asyncio
import json
import sqlite3
import uuid
from urllib.parse import urlsplit

from rookery import rpc
from rookery.account import Account
from rookery.app import handle
from rookery.net import HttpResponse
from rookery.web import Headers, Request


def _rows(cursor) -> list[dict]:
    names = [column[0] for column in cursor.description or []]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


class FakeD1:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")

    async def first(self, query, *params):
        rows = _rows(self.conn.execute(query, params))
        return rows[0] if rows else None

    async def all(self, query, *params):
        return _rows(self.conn.execute(query, params))

    async def run(self, query, *params):
        cursor = self.conn.execute(query, params)
        self.conn.commit()
        return cursor.rowcount

    async def batch(self, statements):
        with self.conn:
            for query, params in statements:
                self.conn.execute(query, params)


class FakeSql:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")

    def exec(self, query, *params):
        cursor = self.conn.execute(query, params)
        rows = _rows(cursor)
        self.conn.commit()
        return rows


class NullSequencer:
    async def sequence_commit(self, **_):
        pass

    async def sequence_identity(self, **_):
        pass

    async def sequence_account(self, **_):
        pass


class FakeBlobs:
    def __init__(self):
        self.objects = {}

    async def put(self, key, data, content_type):
        self.objects[key] = (bytes(data), content_type)

    async def get(self, key):
        return self.objects.get(key)

    async def list(self, prefix, cursor=None):
        return [key for key in self.objects if key.startswith(prefix)], None

    async def delete(self, keys):
        for key in keys:
            self.objects.pop(key, None)


class FakeHttp:
    """PLC at https://plc.test; this PDS at its own hostname; `routes[url_prefix] = async fn(url, kw)`."""

    def __init__(self, env):
        self.env = env
        self.plc_ops = {}
        self.routes = {}
        self.calls = []

    async def fetch(self, url, method="GET", headers=None, body=None, timeout=None, redirect=None):
        self.calls.append((method, url))
        parts = urlsplit(url)
        if url.startswith(self.env.ROOKERY_PLC_URL + "/"):
            did = parts.path.strip("/").split("/")[0]
            if method == "POST":
                self.plc_ops[did] = json.loads(body)
                return HttpResponse(200, b"{}")
            op = self.plc_ops.get(did)
            if op is None:
                return HttpResponse(404, b"{}")
            return HttpResponse(200, json.dumps(plc_doc(did, op)).encode())
        for prefix, handler in self.routes.items():
            if url.startswith(prefix):
                return await handler(url, method=method, headers=headers or {}, body=body)
        if parts.hostname == self.env.ROOKERY_HOSTNAME:
            response = await self.env.request(method, parts.path + (f"?{parts.query}" if parts.query else ""),
                                              headers=headers or {}, body=body)
            return HttpResponse(response.status, response.body, {k.lower(): v for k, v in response.headers})
        return HttpResponse(404, b"not found")


def plc_doc(did, op):
    return {
        "id": did,
        "alsoKnownAs": op["alsoKnownAs"],
        "verificationMethod": [
            {"id": f"{did}#{name}", "type": "Multikey", "controller": did,
             "publicKeyMultibase": key.removeprefix("did:key:")}
            for name, key in op["verificationMethods"].items()
        ],
        "service": [
            {"id": f"#{name}", "type": service["type"], "serviceEndpoint": service["endpoint"]}
            for name, service in op["services"].items()
        ],
    }


class FakeEnv:
    ROOKERY_HOSTNAME = "pds.test"
    ROOKERY_HANDLE_DOMAIN = ".pds.test"
    ROOKERY_PLC_URL = "https://plc.test"
    OAUTH_NONCE_SECRET = "test-secret"

    def __init__(self, variant=None):
        self.ROOKERY_VARIANT = variant
        self.db = FakeD1()
        self.blobs = FakeBlobs()
        self.http = FakeHttp(self)
        self.sequencer = NullSequencer()
        self.accounts = {}
        self.pending = []

    def __getattr__(self, name):
        if name.isupper():
            return None
        raise AttributeError(name)

    def new_account_id(self):
        return uuid.uuid4().hex

    def account(self, do_id):
        if do_id not in self.accounts:
            self.accounts[do_id] = Account(FakeSql(), self.sequencer, self.blobs)
        target = self.accounts[do_id]

        async def send(request):
            return await rpc.serve(target, rpc.ACCOUNT_METHODS, request)
        return rpc.AccountClient(send)

    def wait_until(self, coroutine):
        self.pending.append(asyncio.ensure_future(coroutine))

    async def settle(self):
        while self.pending:
            batch, self.pending = self.pending, []
            await asyncio.gather(*batch)

    async def request(self, method, path, headers=None, body=None, json_body=None):
        headers = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers.setdefault("content-type", "application/json")
        if isinstance(body, str):
            body = body.encode()
        request = Request(method, f"https://{self.ROOKERY_HOSTNAME}{path}", Headers(headers.items()), body=body or b"")
        return await handle(request, self)


def body(response):
    return json.loads(response.body) if response.body else None
