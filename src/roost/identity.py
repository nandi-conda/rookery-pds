# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""did:plc identities: the signed genesis operation, and later handle/PDS updates."""

import json

from . import cbor
from .encoding import b32_encode, b64url_encode, sha256
from .keys import Secp256k1Keypair


class PlcError(Exception):
    pass


def _agentbus_service(endpoint: str | None) -> dict:
    return {"agentbus": {"type": "AgentBusEndpoint", "endpoint": endpoint}} if endpoint else {}


def did_credentials(handle: str, pds_endpoint: str, signing_did: str, rotation_did: str,
                    agentbus_endpoint: str | None = None) -> dict:
    """The identity fields a roost account's DID document should carry
    (com.atproto.identity.getRecommendedDidCredentials, and the genesis op)."""
    return {
        "rotationKeys": [rotation_did],
        "verificationMethods": {"atproto": signing_did},
        "alsoKnownAs": [f"at://{handle}"],
        "services": {
            "atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": pds_endpoint},
            **_agentbus_service(agentbus_endpoint),
        },
    }


def build_unsigned_genesis_op(handle: str, hostname: str, signing: Secp256k1Keypair,
                              rotation: Secp256k1Keypair, agentbus_endpoint: str | None = None) -> dict:
    credentials = did_credentials(handle, f"https://{hostname}", signing.did(), rotation.did(), agentbus_endpoint)
    return {"type": "plc_operation", **credentials, "prev": None}


def sign_genesis_op(unsigned: dict, rotation: Secp256k1Keypair) -> tuple[dict, str]:
    signed = dict(unsigned, sig=b64url_encode(rotation.sign(cbor.encode(unsigned))))
    did = "did:plc:" + b32_encode(sha256(cbor.encode(signed)))[:24]
    return signed, did


async def _post_op(http, plc_url: str, did: str, op: dict) -> None:
    response = await http.fetch(
        f"{plc_url}/{did}", method="POST", headers={"Content-Type": "application/json"},
        body=json.dumps(op, separators=(",", ":")),
    )
    if not response.ok:
        raise PlcError(f"PLC directory rejected operation ({response.status}): {response.text()}")


async def create_plc_did(http, handle: str, hostname: str, signing: Secp256k1Keypair, rotation: Secp256k1Keypair,
                         plc_url: str, agentbus_endpoint: str | None = None) -> str:
    signed, did = sign_genesis_op(
        build_unsigned_genesis_op(handle, hostname, signing, rotation, agentbus_endpoint), rotation
    )
    await _post_op(http, plc_url, did, signed)
    return did


async def update_plc_handle(http, did: str, handle: str, pds_endpoint: str, sign_with_rotation_key,
                            plc_url: str, agentbus_endpoint: str | None = None) -> None:
    """Point a did:plc at `handle` and `pds_endpoint`, signed by the account's
    rotation key (held by the Account DO, reached through `sign_with_rotation_key`,
    which returns {key_did, sig})."""
    log_response = await http.fetch(f"{plc_url}/{did}/log/audit")
    if not log_response.ok:
        raise PlcError(f"PLC directory audit log fetch failed ({log_response.status})")
    live = [entry for entry in log_response.json() if not entry.get("nullified")]
    last = live[-1] if live else None
    if not last or last["operation"].get("type") != "plc_operation":
        raise PlcError("PLC directory has no current plc_operation for this DID")
    prev_op = {key: value for key, value in last["operation"].items() if key != "sig"}
    unsigned = dict(
        prev_op,
        alsoKnownAs=[f"at://{handle}"],
        services={
            **prev_op.get("services", {}),
            "atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": pds_endpoint},
            **_agentbus_service(agentbus_endpoint),
        },
        prev=last["cid"],
    )
    signed_by = await sign_with_rotation_key(cbor.encode(unsigned))
    if signed_by["key_did"] not in last["operation"].get("rotationKeys", []):
        raise PlcError("Account rotation key is not a rotation key for this DID")
    await _post_op(http, plc_url, did, dict(unsigned, sig=b64url_encode(bytes(signed_by["sig"]))))
