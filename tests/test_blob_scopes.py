# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""blob: permission scopes (atproto.com/specs/permission#blob)."""

import pytest

from roost.oauth.scopes import enforce_scope, parse_scope


@pytest.mark.parametrize("token", [
    "blob:*/*", "blob:image/*", "blob:application/vnd.sealight.automerge.amch", "blob:image%2Fpng",
    "blob?accept=image/*&accept=video/mp4",
])
def test_accepts_mime_patterns(token):
    assert parse_scope(f"atproto {token}") is not None


@pytest.mark.parametrize("token", ["blob:", "blob:image", "blob:*/png", "blob:image/*?mime=x", "blob?accept=", "blob"])
def test_rejects_malformed_blob_scopes(token):
    assert parse_scope(f"atproto {token}") is None


@pytest.mark.parametrize("scope,mime,allowed", [
    ("atproto blob:*/*", "text/plain", True),
    ("atproto blob:image/*", "image/png", True),
    ("atproto blob:image/*", "video/mp4", False),
    ("atproto blob:application/vnd.sealight.automerge.amch", "application/vnd.sealight.automerge.amch", True),
    ("atproto blob:application/vnd.sealight.automerge.amch", "application/octet-stream", False),
    ("atproto blob?accept=image/*&accept=video/mp4", "video/mp4; codecs=avc1", True),
    ("atproto repo:a.b.c", "image/png", False),
    ("atproto transition:generic", "image/png", True),
])
def test_upload_blob_checks_the_mime_type(scope, mime, allowed):
    assert (enforce_scope(scope, "uploadBlob", [], mime) is None) is allowed
