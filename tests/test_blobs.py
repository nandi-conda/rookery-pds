# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Blobs: bytes in R2 under did/cid, metadata in the account's DO, served by getBlob."""

UPLOAD = "/xrpc/com.atproto.repo.uploadBlob"


async def upload(rook, data: bytes, mime_type: str) -> dict:
    response = await rook.client.post(UPLOAD, body=data, headers=dict(
        rook.agent.auth_headers("POST", UPLOAD), **{"content-type": mime_type, "content-length": str(len(data))}))
    assert response.status == 200, response.text
    return response.json()["blob"]


async def test_upload_stores_bytes_and_content_type_in_r2(env, enroll):
    rook = await enroll()
    blob = await upload(rook, b"hello blob world", "text/plain")
    assert blob["$type"] == "blob" and blob["ref"]["$link"]
    assert blob["mimeType"] == "text/plain" and blob["size"] == len(b"hello blob world")
    assert env.blobs.objects[f"{rook.did}/{blob['ref']['$link']}"] == (b"hello blob world", "text/plain")


async def test_lists_an_accounts_blobs(client, env, enroll):
    rook = await enroll()
    await upload(rook, b"blob1", "text/plain")
    await upload(rook, b"blob2", "image/png")
    listed = await client.get("/xrpc/com.atproto.sync.listBlobs", params={"did": rook.did})
    assert listed.status == 200
    cids = listed.json()["cids"]
    assert len(cids) == 2 and all(isinstance(cid, str) and cid for cid in cids)


async def test_get_blob_serves_the_stored_content_type(client, enroll):
    rook = await enroll()
    blob = await upload(rook, b"image data here", "image/jpeg")
    response = await client.get("/xrpc/com.atproto.sync.getBlob", params={"did": rook.did, "cid": blob["ref"]["$link"]})
    assert response.status == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.body == b"image data here"


async def test_cids_are_content_addressed(enroll):
    rook = await enroll()
    first = await upload(rook, b"duplicate content", "text/plain")
    second = await upload(rook, b"duplicate content", "text/plain")
    assert first["ref"]["$link"] == second["ref"]["$link"]
