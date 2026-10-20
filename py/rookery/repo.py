# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Signed repo commits (atproto repo v3) over RepoStorage.

A write batch updates the MST, signs a new commit, and returns what the
firehose needs: the new blocks, covering proofs for each touched key (sync
v1.1), and each op with its new and previous record CID.
"""

from dataclasses import dataclass, field

from . import cbor
from .cbor import CID
from .keys import Secp256k1Keypair
from .mst import MST
from .storage import RepoStorage
from .tid import next_tid


class RepoError(ValueError):
    """A write the repo cannot apply (missing record, duplicate key, bad key)."""


class _TrackingStore:
    """Block store view that remembers which MST nodes were read."""

    def __init__(self, storage: RepoStorage):
        self.storage = storage
        self.read: set[CID] = set()

    def get_block(self, cid: CID) -> bytes | None:
        self.read.add(cid)
        return self.storage.get_block(cid)

    def has_block(self, cid: CID) -> bool:
        return self.storage.has_block(cid)


@dataclass
class Write:
    action: str  # "create" | "update" | "delete"
    collection: str
    rkey: str
    record: object = None  # lex value for create/update


@dataclass
class CommitResult:
    cid: CID
    rev: str
    since: str | None
    prev_data: CID | None
    data: CID
    blocks: dict  # CID -> bytes, everything a firehose consumer needs
    ops: list = field(default_factory=list)  # {action, path, cid, prev}


def _sign_commit(did: str, rev: str, data: CID, keypair: Secp256k1Keypair) -> bytes:
    unsigned = {"did": did, "version": 3, "rev": rev, "prev": None, "data": data}
    signed = dict(unsigned, sig=keypair.sign(cbor.encode(unsigned)))
    return cbor.encode(signed)


class Repo:
    def __init__(self, storage: RepoStorage, did: str, commit_cid: CID, commit: dict):
        self.storage = storage
        self.did = did
        self.cid = commit_cid
        self.commit = commit
        self.tracker = _TrackingStore(storage)
        self.data = MST.load(self.tracker, commit["data"])

    @classmethod
    def load(cls, storage: RepoStorage) -> "Repo | None":
        state = storage.get_state()
        if not state or not state.get("root_cid"):
            return None
        commit_cid = CID.parse(state["root_cid"])
        raw = storage.get_block(commit_cid)
        if raw is None:
            raise RepoError(f"Missing commit block {commit_cid}")
        commit = cbor.decode(raw)
        return cls(storage, commit["did"], commit_cid, commit)

    @classmethod
    def create(cls, storage: RepoStorage, did: str, keypair: Secp256k1Keypair) -> "Repo":
        data = MST.create(_TrackingStore(storage), [])
        data_cid, data_bytes = data.serialize()
        rev = next_tid()
        commit_bytes = _sign_commit(did, rev, data_cid, keypair)
        commit_cid = CID.for_cbor(commit_bytes)
        storage.apply_commit(
            cid=commit_cid, rev=rev, data_cid=data_cid,
            new_blocks={data_cid: data_bytes, commit_cid: commit_bytes}, removed=set(),
        )
        return cls.load(storage)

    @property
    def rev(self) -> str:
        return self.commit["rev"]

    def get_record(self, collection: str, rkey: str) -> tuple[CID, object] | None:
        cid = self.data.get(f"{collection}/{rkey}")
        if cid is None:
            return None
        raw = self.storage.get_block(cid)
        if raw is None:
            return None
        return cid, cbor.decode(raw)

    def walk_records(self, start: str = ""):
        """(collection, rkey, cid) for every record with key >= start."""
        seen = None
        for leaf in self.data.walk_leaves_from(start):
            if leaf.key == seen:
                continue
            seen = leaf.key
            collection, rkey = leaf.key.split("/", 1)
            yield collection, rkey, leaf.value

    def read_record(self, cid: CID):
        raw = self.storage.get_block(cid)
        return None if raw is None else cbor.decode(raw)

    def apply_writes(self, writes: list[Write], keypair: Secp256k1Keypair) -> CommitResult:
        data = self.data
        leaf_blocks: dict[CID, bytes] = {}
        removed_leaves: set[CID] = set()
        ops = []
        for write in writes:
            key = f"{write.collection}/{write.rkey}"
            try:
                prev = data.get(key)
                if write.action == "delete":
                    if prev is None:
                        raise KeyError(f"Could not find a record with key: {key}")
                    data = data.delete(key)
                    removed_leaves.add(prev)
                    ops.append({"action": "delete", "path": key, "cid": None, "prev": prev})
                    continue
                raw = cbor.encode(write.record)
                cid = CID.for_cbor(raw)
                leaf_blocks[cid] = raw
                if write.action == "create":
                    data = data.add(key, cid)
                elif write.action == "update":
                    data = data.update(key, cid)
                    if prev != cid:
                        removed_leaves.add(prev)
                else:
                    raise RepoError(f"Unknown write action {write.action}")
                op = {"action": write.action, "path": key, "cid": cid}
                if write.action == "update":
                    op["prev"] = prev
                ops.append(op)
            except (KeyError, ValueError) as exc:
                if isinstance(exc, RepoError):
                    raise
                raise RepoError(str(exc.args[0]) if exc.args else str(exc)) from exc

        data_cid, mst_blocks = data.get_unstored_blocks()
        removed: set[CID] = set(self.tracker.read) - _loaded_node_cids(data)
        removed.add(self.cid)
        if removed_leaves - set(leaf_blocks):
            still_referenced = {leaf.value for leaf in data.leaves()}
            removed |= (removed_leaves - set(leaf_blocks)) - still_referenced

        rev = next_tid(self.rev)
        commit_bytes = _sign_commit(self.did, rev, data_cid, keypair)
        commit_cid = CID.for_cbor(commit_bytes)
        new_blocks = dict(mst_blocks)
        new_blocks.update(leaf_blocks)
        new_blocks[commit_cid] = commit_bytes
        self.storage.apply_commit(
            cid=commit_cid, rev=rev, data_cid=data_cid, new_blocks=new_blocks, removed=removed,
        )

        firehose_blocks = dict(new_blocks)
        for write in writes:
            firehose_blocks.update(data.get_covering_proof(f"{write.collection}/{write.rkey}"))
        return CommitResult(
            cid=commit_cid,
            rev=rev,
            since=self.rev,
            prev_data=self.commit["data"],
            data=data_cid,
            blocks=firehose_blocks,
            ops=ops,
        )


def _loaded_node_cids(root: MST) -> set[CID]:
    """CIDs of the new tree's nodes that are in memory (new or read this commit)."""
    out: set[CID] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        cid = node.get_pointer()
        if cid in out:
            continue
        out.add(cid)
        if node.entries is None:
            continue
        stack.extend(entry for entry in node.entries if entry.is_tree())
    return out
