# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

async def test_signup_and_write(client, enroll):
    rook = await enroll()
    response = await rook.create("com.example.test", {"text": "hello"}, rkey="post1")
    assert response.status == 200, response.text
    got = await client.get("/xrpc/com.atproto.repo.getRecord", params={"repo": rook.did, "collection": "com.example.test", "rkey": "post1"})
    assert got.json()["value"] == {"text": "hello"}
