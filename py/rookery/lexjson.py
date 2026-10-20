# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Conversion between the JSON and IPLD forms of AT data model values.

JSON `{"$link": cid}` maps to a CID and `{"$bytes": base64}` to bytes, as in
@atproto/lex-json; everything else passes through.
"""

from .cbor import CID, CborError
from .encoding import b64_decode, b64_encode_nopad


def json_to_lex(value):
    if isinstance(value, list):
        return [json_to_lex(item) for item in value]
    if isinstance(value, dict):
        if len(value) == 1 and "$link" in value and isinstance(value["$link"], str):
            try:
                return CID.parse(value["$link"])
            except CborError:
                pass
        if len(value) == 1 and "$bytes" in value and isinstance(value["$bytes"], str):
            try:
                return b64_decode(value["$bytes"])
            except ValueError:
                pass
        return {key: json_to_lex(item) for key, item in value.items()}
    return value


def lex_to_json(value):
    if isinstance(value, CID):
        return {"$link": str(value)}
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": b64_encode_nopad(bytes(value))}
    if isinstance(value, list):
        return [lex_to_json(item) for item in value]
    if isinstance(value, dict):
        return {key: lex_to_json(item) for key, item in value.items()}
    return value
