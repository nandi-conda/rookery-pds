# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Space references: at://<authority>/space/<type>/<skey>, as SpaceRef in @atproto/syntax."""

from dataclasses import dataclass

from ..syntax import is_valid_did, is_valid_nsid, is_valid_record_key

SPACE_MARKER = "space"


class InvalidSpaceRef(ValueError):
    pass


@dataclass(frozen=True)
class SpaceRef:
    did: str
    type: str
    skey: str

    @classmethod
    def parse(cls, uri) -> "SpaceRef":
        if not isinstance(uri, str) or not uri.startswith("at://"):
            raise InvalidSpaceRef(f"Not a space uri: {uri}")
        parts = uri[len("at://"):].split("/")
        if len(parts) != 4 or parts[1] != SPACE_MARKER:
            raise InvalidSpaceRef(f"Not a space uri: {uri}")
        did, _, space_type, skey = parts
        if not is_valid_did(did) or not is_valid_nsid(space_type) or not is_valid_record_key(skey):
            raise InvalidSpaceRef(f"Not a space uri: {uri}")
        return cls(did, space_type, skey)

    def __str__(self) -> str:
        return f"at://{self.did}/{SPACE_MARKER}/{self.type}/{self.skey}"

    def record_uri(self, author: str, collection: str, rkey: str) -> str:
        return f"{self}/{author}/{collection}/{rkey}"


def space_host_aud(space_did: str) -> str:
    """The audience a delegation token, client attestation or notifyWrite names for a
    space authority: its PDS, which is its space host."""
    return f"{space_did}#atproto_pds"
