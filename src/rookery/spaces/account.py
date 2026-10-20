# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The Account Durable Object's space methods, mixed into Account.

Space data for an account lives in that account's own DO, beside its public
repo, and its signing key never leaves: commits and space tokens are signed here.
"""

import time

from .. import cbor
from ..cbor import CID
from ..errors import XrpcError
from ..lexjson import json_to_lex
from ..syntax import is_valid_nsid, is_valid_record_key
from ..tid import next_tid
from .lthash import LtHash
from .refs import InvalidSpaceRef, SpaceRef
from .store import SpaceStore
from .tokens import build_token

MAX_WRITES = 200
WRITE_TYPES = {
    "com.atproto.space.applyWrites#create": "create",
    "com.atproto.space.applyWrites#update": "update",
    "com.atproto.space.applyWrites#delete": "delete",
}

SPACE_METHODS = frozenset({
    "space_create", "space_update", "space_get", "space_status", "space_delete", "space_put_member",
    "space_remove_member", "space_list_members", "space_get_member", "space_record_writer",
    "space_list_writers", "space_register_recipient", "space_unregister_recipient", "space_recipients",
    "space_apply_writes", "space_put_record", "space_get_record", "space_list_records", "space_list_repo_ops",
    "space_latest_commit", "space_export_car", "space_list_blobs", "space_has_blob", "space_list_spaces",
    "space_sign_token", "space_signing_key", "space_queue_notification", "space_clear_notification",
    "space_due_notifications",
})


def parse_space(space) -> SpaceRef:
    try:
        return SpaceRef.parse(space)
    except InvalidSpaceRef as exc:
        raise XrpcError("InvalidRequest", str(exc)) from exc


def prepare_write(did: str, ref: SpaceRef, action: str, collection, rkey, record=None) -> dict:
    """{action, collection, rkey, uri, cid?, value?}: a write validated and encoded."""
    if not is_valid_nsid(collection):
        raise XrpcError("InvalidRequest", f"Invalid collection: {collection}")
    if rkey is None and action == "create":
        rkey = next_tid()
    if not is_valid_record_key(rkey):
        raise XrpcError("InvalidRequest", f"Invalid record key: {rkey}")
    write = {"action": action, "collection": collection, "rkey": rkey,
             "uri": ref.record_uri(did, collection, rkey)}
    if action == "delete":
        return write
    if not isinstance(record, dict):
        raise XrpcError("InvalidRecord", "Record must be an object")
    record_type = record.get("$type", collection)
    if record_type != collection:
        raise XrpcError("InvalidRecord", f"Record $type {record_type} does not match collection {collection}")
    lex = json_to_lex(dict(record, **{"$type": collection}))
    try:
        value = cbor.encode(lex)
    except cbor.CborError as exc:
        raise XrpcError("InvalidRecord", f"Invalid record: {exc}") from exc
    return dict(write, cid=str(CID.for_cbor(value)), value=value)


def write_result(write: dict) -> dict:
    if write["action"] == "delete":
        return {"$type": "com.atproto.space.applyWrites#deleteResult"}
    return {
        "$type": f"com.atproto.space.applyWrites#{write['action']}Result",
        "uri": write["uri"], "cid": write["cid"], "validationStatus": "unknown",
    }


class SpaceMethods:
    """Needs self.storage (RepoStorage, for its sql and blobs), self._state() and self._keypair()."""

    @property
    def spaces(self) -> SpaceStore:
        store = getattr(self, "_spaces", None)
        if store is None:
            store = self._spaces = SpaceStore(self.storage.sql)
        return store

    def _did(self) -> str:
        return self._state()["did"]

    def _commit_out(self, commit: dict | None) -> dict | None:
        if commit is None:
            return None
        return {"rev": commit["rev"], "hash": LtHash(commit["set_hash"]).digest()}

    def _known_blob(self, cid: str) -> bool:
        return bool(self.storage.sql.exec("SELECT 1 AS x FROM blobs WHERE cid = ? LIMIT 1", cid))

    # Governance (this account is the space authority)

    async def space_create(self, space: str, config: dict) -> None:
        self.spaces.create_space(space, config)

    async def space_update(self, space: str, config: dict) -> None:
        self.spaces.update_config(space, config)

    async def space_get(self, space: str) -> dict:
        return self.spaces.get_active_config(space)

    async def space_status(self, space: str) -> dict:
        existing = self.spaces.get_space(space)
        return {"deleted": bool(existing and existing["deleted_at"]), "config": self.spaces.get_config(space)}

    async def space_delete(self, space: str) -> list[str]:
        return self.spaces.delete_space(space)

    async def space_put_member(self, space: str, did: str, read: bool, write: bool) -> None:
        self.spaces.put_member(space, did, read, write)

    async def space_remove_member(self, space: str, did: str) -> None:
        self.spaces.remove_member(space, did)

    async def space_list_members(self, space: str, limit: int, cursor: str | None = None) -> list[dict]:
        return self.spaces.list_members(space, limit, cursor)

    async def space_get_member(self, space: str, did: str) -> dict | None:
        return self.spaces.get_member(space, did)

    async def space_record_writer(self, space: str, did: str, repo_rev: str, hash: bytes) -> dict | None:
        return self.spaces.record_writer(space, did, repo_rev, hash)

    async def space_list_writers(self, space: str, limit: int, cursor: str | None = None) -> list[dict]:
        return self.spaces.list_writers(space, limit, cursor)

    async def space_register_recipient(self, space: str, service: str, endpoint: str) -> str:
        return self.spaces.register_recipient(space, service, endpoint)

    async def space_unregister_recipient(self, space: str, service: str) -> None:
        self.spaces.unregister_recipient(space, service)

    async def space_recipients(self, space: str) -> list[dict]:
        return self.spaces.get_recipients(space)

    # This account's repo in a space

    async def space_apply_writes(self, space: str, writes: list) -> dict:
        did, ref = self._did(), parse_space(space)
        if len(writes) > MAX_WRITES:
            raise XrpcError("InvalidRequest", f"Too many writes. Max: {MAX_WRITES}")
        prepared = []
        for write in writes:
            action = WRITE_TYPES.get(write.get("$type")) if isinstance(write, dict) else None
            if action is None:
                raise XrpcError("InvalidRequest", f"Action not supported: {write}")
            if action != "create" and not write.get("rkey"):
                raise XrpcError("InvalidRequest", f"{action} requires rkey")
            prepared.append(prepare_write(did, ref, action, write.get("collection"), write.get("rkey"),
                                          write.get("value")))
        commit = self.spaces.apply_writes(did, space, prepared, self._known_blob)
        return {"results": [write_result(write) for write in prepared], "commit": self._commit_out(commit)}

    async def space_put_record(self, space: str, collection: str, rkey: str, record, mode: str = "put") -> dict:
        """mode "create" | "put" (create or update) | "delete"; returns the write and commit."""
        did, ref = self._did(), parse_space(space)
        uri = ref.record_uri(did, collection, rkey) if rkey else None
        if mode == "put":
            action = "update" if uri and self.spaces.has_record(uri) else "create"
        elif mode == "delete":
            if uri and not self.spaces.has_record(uri):
                return {"action": "delete", "write": None, "commit": None}
            action = "delete"
        else:
            action = "create"
        write = prepare_write(did, ref, action, collection, rkey, record)
        commit = self.spaces.apply_writes(did, space, [write], self._known_blob)
        return {"action": action, "write": write_result(write), "commit": self._commit_out(commit)}

    async def space_get_record(self, space: str, collection: str, rkey: str) -> dict | None:
        ref = parse_space(space)
        uri = ref.record_uri(self._did(), collection, rkey)
        record = self.spaces.get_record(uri)
        return dict(record, uri=uri) if record else None

    async def space_list_records(self, space: str, limit: int, cursor: str | None = None, reverse: bool = False,
                                 collection: str | None = None, exclude_values: bool = False) -> list[dict]:
        return self.spaces.list_records(space, limit, cursor, reverse, collection, exclude_values)

    async def space_list_repo_ops(self, space: str, limit: int, since: str | None = None, cursor: list | None = None,
                                  exclude_values: bool = False) -> dict:
        ops = self.spaces.list_repo_ops(space, limit, since, tuple(cursor) if cursor else None, exclude_values)
        commit = None if len(ops) == limit else self.spaces.signed_commit(space, self._did(), self._keypair())
        return {"ops": ops, "commit": commit}

    async def space_latest_commit(self, space: str) -> dict | None:
        return self.spaces.signed_commit(space, self._did(), self._keypair())

    async def space_export_car(self, space: str, exclude_values: bool = False) -> bytes | None:
        commit = self.spaces.signed_commit(space, self._did(), self._keypair())
        return None if commit is None else self.spaces.export_car(space, commit, exclude_values)

    async def space_list_blobs(self, space: str, limit: int, since: str | None = None,
                               cursor: str | None = None) -> list[str]:
        return self.spaces.list_blobs(space, limit, since, cursor)

    async def space_has_blob(self, space: str, cid: str) -> bool:
        return self.spaces.is_blob_in_space(space, cid)

    async def space_list_spaces(self, limit: int, cursor: str | None = None, space_type: str | None = None,
                                authority: str | None = None) -> list[str]:
        return self.spaces.list_spaces(limit, cursor, space_type, authority)

    # Keys

    async def space_sign_token(self, token_type: str, sub: str, aud: str | None = None,
                               key_id: str | None = None) -> str:
        if token_type not in ("delegation", "credential"):
            raise XrpcError("InvalidRequest", f"cannot mint a {token_type} token")
        return build_token(token_type, self._keypair().sign, iss=self._did(), sub=sub, aud=aud, key_id=key_id)

    async def space_signing_key(self) -> str:
        return self._keypair().did()

    # Write notifications owed to space hosts

    async def space_queue_notification(self, space: str, repo_rev: str, hash: bytes, attempts: int,
                                       retry_at: int, expires_at: int) -> None:
        self.spaces.queue_notification(space, repo_rev, hash, attempts, retry_at, expires_at)

    async def space_clear_notification(self, space: str, repo_rev: str) -> None:
        self.spaces.clear_notification(space, repo_rev)

    async def space_due_notifications(self) -> list[dict]:
        return self.spaces.due_notifications(int(time.time() * 1000))
