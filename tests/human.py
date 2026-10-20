# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Password accounts for tests: sign up through createAccount and call XRPC with the session."""

HANDLE_DOMAIN = ".rookery.test"
PASSWORD = "long enough pw"


async def sign_up(client, name: str, password: str = PASSWORD, **extra):
    return await client.post("/xrpc/com.atproto.server.createAccount",
                             json_body={"handle": f"{name}{HANDLE_DOMAIN}", "password": password, **extra})


async def human(client, name: str) -> dict:
    """{did, handle, auth} for a new password account."""
    response = await sign_up(client, name)
    assert response.status == 200, response.body
    created = response.json()
    return {"did": created["did"], "handle": created["handle"],
            "auth": {"authorization": f"Bearer {created['accessJwt']}"}, "session": created}


async def call(client, method: str, path: str, who: dict | None = None, headers: dict | None = None,
               expect: int = 200, **json_body):
    """The JSON body (or the response, for non-JSON) after asserting the status."""
    all_headers = dict(who["auth"] if who else {}, **(headers or {}))
    response = await client.request(method, path, headers=all_headers, json_body=json_body or None)
    assert response.status == expect, (path, response.status, response.body)
    if response.headers.get("content-type") == "application/json":
        return response.json()
    return response
