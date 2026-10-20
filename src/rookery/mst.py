# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Merkle Search Tree, ported operation for operation from @atproto/repo.

Keeping the exact add/delete/split/merge algorithm (not just the canonical
shape) means trees written by the TypeScript rookery and by this port always
agree block for block. Nodes load lazily from a block store with a synchronous
`get_block(cid) -> bytes | None`; nothing is ever mutated, every edit returns a
new tree that shares unchanged subtrees.
"""

import re

from . import cbor
from .cbor import CID
from .encoding import sha256

_VALID_CHARS = re.compile(r"^[a-zA-Z0-9_~\-:.]*$")


class MissingBlockError(Exception):
    pass


class InvalidMstKeyError(ValueError):
    pass


def is_valid_mst_key(key: str) -> bool:
    parts = key.split("/")
    return (
        len(key) <= 1024
        and len(parts) == 2
        and len(parts[0]) > 0
        and len(parts[1]) > 0
        and bool(_VALID_CHARS.match(parts[0]))
        and bool(_VALID_CHARS.match(parts[1]))
    )


def ensure_valid_mst_key(key: str) -> None:
    if not is_valid_mst_key(key):
        raise InvalidMstKeyError(f"Not a valid MST key: {key}")


def leading_zeros_on_hash(key: str | bytes) -> int:
    digest = sha256(key if isinstance(key, bytes) else key.encode("utf-8"))
    zeros = 0
    for byte in digest:
        if byte < 64:
            zeros += 1
        if byte < 16:
            zeros += 1
        if byte < 4:
            zeros += 1
        if byte == 0:
            zeros += 1
        else:
            break
    return zeros


def _prefix_len(a: str, b: str) -> int:
    count = 0
    for x, y in zip(a, b):
        if x != y:
            break
        count += 1
    return count


class Leaf:
    __slots__ = ("key", "value")

    def __init__(self, key: str, value: CID):
        self.key = key
        self.value = value

    def is_leaf(self) -> bool:
        return True

    def is_tree(self) -> bool:
        return False


def serialize_node_data(entries: list) -> dict:
    data = {"l": None, "e": []}
    i = 0
    if entries and entries[0].is_tree():
        i = 1
        data["l"] = entries[0].get_pointer()
    last_key = ""
    while i < len(entries):
        leaf = entries[i]
        nxt = entries[i + 1] if i + 1 < len(entries) else None
        if not leaf.is_leaf():
            raise ValueError("Not a valid node: two subtrees next to each other")
        i += 1
        subtree = None
        if nxt is not None and nxt.is_tree():
            subtree = nxt.get_pointer()
            i += 1
        ensure_valid_mst_key(leaf.key)
        prefix = _prefix_len(last_key, leaf.key)
        data["e"].append(
            {"p": prefix, "k": leaf.key[prefix:].encode("ascii"), "v": leaf.value, "t": subtree}
        )
        last_key = leaf.key
    return data


class MST:
    def __init__(self, storage, pointer: CID | None, entries: list | None, layer: int | None):
        self.storage = storage
        self.pointer = pointer
        self.entries = entries
        self.layer = layer
        self.outdated_pointer = False

    @classmethod
    def create(cls, storage, entries: list | None = None, layer: int | None = None) -> "MST":
        entries = entries or []
        node = cls(storage, None, entries, layer)
        node.pointer = CID.for_cbor(cbor.encode(serialize_node_data(entries)))
        return node

    @classmethod
    def load(cls, storage, cid: CID, layer: int | None = None) -> "MST":
        return cls(storage, cid, None, layer)

    def new_tree(self, entries: list) -> "MST":
        node = MST(self.storage, self.pointer, entries, self.layer)
        node.outdated_pointer = True
        return node

    def is_leaf(self) -> bool:
        return False

    def is_tree(self) -> bool:
        return True

    # Lazy loading

    def get_entries(self) -> list:
        if self.entries is not None:
            return list(self.entries)
        if self.pointer is None:
            raise ValueError("No entries or CID provided")
        raw = self.storage.get_block(self.pointer)
        if raw is None:
            raise MissingBlockError(f"Missing MST node {self.pointer}")
        data = cbor.decode(raw)
        layer = leading_zeros_on_hash(data["e"][0]["k"]) if data["e"] else None
        self.entries = _deserialize_node_data(self.storage, data, layer)
        return list(self.entries)

    def get_pointer(self) -> CID:
        if not self.outdated_pointer:
            return self.pointer
        cid, _ = self.serialize()
        self.pointer = cid
        self.outdated_pointer = False
        return self.pointer

    def serialize(self) -> tuple[CID, bytes]:
        entries = self.get_entries()
        for entry in entries:
            if entry.is_tree() and entry.outdated_pointer:
                entry.get_pointer()
        raw = cbor.encode(serialize_node_data(entries))
        return CID.for_cbor(raw), raw

    def get_layer(self) -> int:
        self.layer = self._attempt_get_layer()
        if self.layer is None:
            self.layer = 0
        return self.layer

    def _attempt_get_layer(self) -> int | None:
        if self.layer is not None:
            return self.layer
        entries = self.get_entries()
        layer = _layer_for_entries(entries)
        if layer is None:
            for entry in entries:
                if entry.is_tree():
                    child = entry._attempt_get_layer()
                    if child is not None:
                        layer = child + 1
                        break
        if layer is not None:
            self.layer = layer
        return layer

    def get_unstored_blocks(self) -> tuple[CID, dict]:
        blocks: dict[CID, bytes] = {}
        pointer = self.get_pointer()
        if self.storage.has_block(pointer):
            return pointer, blocks
        entries = self.get_entries()
        raw = cbor.encode(serialize_node_data(entries))
        blocks[CID.for_cbor(raw)] = raw
        for entry in entries:
            if entry.is_tree():
                _, sub = entry.get_unstored_blocks()
                blocks.update(sub)
        return pointer, blocks

    # Core operations

    def add(self, key: str, value: CID, known_zeros: int | None = None) -> "MST":
        ensure_valid_mst_key(key)
        key_zeros = known_zeros if known_zeros is not None else leading_zeros_on_hash(key)
        layer = self.get_layer()
        new_leaf = Leaf(key, value)
        if key_zeros == layer:
            index = self.find_gt_or_equal_leaf_index(key)
            found = self.at_index(index)
            if found is not None and found.is_leaf() and found.key == key:
                raise ValueError(f"There is already a value at key: {key}")
            prev = self.at_index(index - 1)
            if prev is None or prev.is_leaf():
                return self.splice_in(new_leaf, index)
            left, right = prev.split_around(key)
            return self.replace_with_split(index - 1, left, new_leaf, right)
        if key_zeros < layer:
            index = self.find_gt_or_equal_leaf_index(key)
            prev = self.at_index(index - 1)
            if prev is not None and prev.is_tree():
                return self.update_entry(index - 1, prev.add(key, value, key_zeros))
            child = self.create_child().add(key, value, key_zeros)
            return self.splice_in(child, index)
        left, right = self.split_around(key)
        layer = self.get_layer()
        for _ in range(1, key_zeros - layer):
            if left is not None:
                left = left.create_parent()
            if right is not None:
                right = right.create_parent()
        updated = []
        if left is not None:
            updated.append(left)
        updated.append(Leaf(key, value))
        if right is not None:
            updated.append(right)
        root = MST.create(self.storage, updated, key_zeros)
        root.outdated_pointer = True
        return root

    def get(self, key: str) -> CID | None:
        index = self.find_gt_or_equal_leaf_index(key)
        found = self.at_index(index)
        if found is not None and found.is_leaf() and found.key == key:
            return found.value
        prev = self.at_index(index - 1)
        if prev is not None and prev.is_tree():
            return prev.get(key)
        return None

    def update(self, key: str, value: CID) -> "MST":
        ensure_valid_mst_key(key)
        index = self.find_gt_or_equal_leaf_index(key)
        found = self.at_index(index)
        if found is not None and found.is_leaf() and found.key == key:
            return self.update_entry(index, Leaf(key, value))
        prev = self.at_index(index - 1)
        if prev is not None and prev.is_tree():
            return self.update_entry(index - 1, prev.update(key, value))
        raise KeyError(f"Could not find a record with key: {key}")

    def delete(self, key: str) -> "MST":
        return self._delete_recurse(key).trim_top()

    def _delete_recurse(self, key: str) -> "MST":
        index = self.find_gt_or_equal_leaf_index(key)
        found = self.at_index(index)
        if found is not None and found.is_leaf() and found.key == key:
            prev = self.at_index(index - 1)
            nxt = self.at_index(index + 1)
            if prev is not None and prev.is_tree() and nxt is not None and nxt.is_tree():
                merged = prev.append_merge(nxt)
                return self.new_tree(self.slice(0, index - 1) + [merged] + self.slice(index + 2))
            return self.remove_entry(index)
        prev = self.at_index(index - 1)
        if prev is not None and prev.is_tree():
            subtree = prev._delete_recurse(key)
            if len(subtree.get_entries()) == 0:
                return self.remove_entry(index - 1)
            return self.update_entry(index - 1, subtree)
        raise KeyError(f"Could not find a record with key: {key}")

    # Simple operations

    def update_entry(self, index: int, entry) -> "MST":
        return self.new_tree(self.slice(0, index) + [entry] + self.slice(index + 1))

    def remove_entry(self, index: int) -> "MST":
        return self.new_tree(self.slice(0, index) + self.slice(index + 1))

    def append(self, entry) -> "MST":
        return self.new_tree(self.get_entries() + [entry])

    def prepend(self, entry) -> "MST":
        return self.new_tree([entry] + self.get_entries())

    def at_index(self, index: int):
        entries = self.get_entries()
        if index < 0 or index >= len(entries):
            return None
        return entries[index]

    def slice(self, start: int, end: int | None = None) -> list:
        entries = self.get_entries()
        # JS slice semantics: a negative start counts from the end.
        if start < 0:
            start = max(len(entries) + start, 0)
        return entries[start:end]

    def splice_in(self, entry, index: int) -> "MST":
        return self.new_tree(self.slice(0, index) + [entry] + self.slice(index))

    def replace_with_split(self, index: int, left, leaf: Leaf, right) -> "MST":
        update = self.slice(0, index)
        if left is not None:
            update.append(left)
        update.append(leaf)
        if right is not None:
            update.append(right)
        update += self.slice(index + 1)
        return self.new_tree(update)

    def trim_top(self) -> "MST":
        try:
            entries = self.get_entries()
        except MissingBlockError:
            return self
        if len(entries) == 1 and entries[0].is_tree():
            return entries[0].trim_top()
        return self

    # Splits and merges

    def split_around(self, key: str):
        index = self.find_gt_or_equal_leaf_index(key)
        left_data = self.slice(0, index)
        right_data = self.slice(index)
        left = self.new_tree(left_data)
        right = self.new_tree(right_data)
        last_in_left = left_data[-1] if left_data else None
        if last_in_left is not None and last_in_left.is_tree():
            left = left.remove_entry(len(left_data) - 1)
            split_left, split_right = last_in_left.split_around(key)
            if split_left is not None:
                left = left.append(split_left)
            if split_right is not None:
                right = right.prepend(split_right)
        return (
            left if len(left.get_entries()) > 0 else None,
            right if len(right.get_entries()) > 0 else None,
        )

    def append_merge(self, to_merge: "MST") -> "MST":
        if self.get_layer() != to_merge.get_layer():
            raise ValueError("Trying to merge two nodes from different layers of the MST")
        these = self.get_entries()
        those = to_merge.get_entries()
        last_in_left = these[-1] if these else None
        first_in_right = those[0] if those else None
        if (
            last_in_left is not None
            and last_in_left.is_tree()
            and first_in_right is not None
            and first_in_right.is_tree()
        ):
            merged = last_in_left.append_merge(first_in_right)
            return self.new_tree(these[:-1] + [merged] + those[1:])
        return self.new_tree(these + those)

    def create_child(self) -> "MST":
        return MST.create(self.storage, [], self.get_layer() - 1)

    def create_parent(self) -> "MST":
        parent = MST.create(self.storage, [self], self.get_layer() + 1)
        parent.outdated_pointer = True
        return parent

    def find_gt_or_equal_leaf_index(self, key: str) -> int:
        entries = self.get_entries()
        for i, entry in enumerate(entries):
            if entry.is_leaf() and entry.key >= key:
                return i
        return len(entries)

    # Traversal

    def walk_leaves_from(self, key: str):
        """Leaves with key >= `key` in order (the cursor key itself included)."""
        index = self.find_gt_or_equal_leaf_index(key)
        entries = self.get_entries()
        found = entries[index] if index < len(entries) else None
        if found is not None and found.is_leaf() and found.key == key:
            yield found
        else:
            prev = entries[index - 1] if index > 0 else None
            if prev is not None:
                if prev.is_leaf() and prev.key == key:
                    yield prev
                elif prev.is_tree():
                    yield from prev.walk_leaves_from(key)
        for entry in entries[index:]:
            if entry.is_leaf():
                yield entry
            else:
                yield from entry.walk_leaves_from(key)

    def leaves(self):
        for entry in self.get_entries():
            if entry.is_leaf():
                yield entry
            else:
                yield from entry.leaves()

    def node_cids(self):
        """Every MST node CID in the tree (leaf records excluded)."""
        yield self.get_pointer()
        for entry in self.get_entries():
            if entry.is_tree():
                yield from entry.node_cids()

    # Covering proofs (sync v1.1): the nodes proving a key and its neighbours.

    def get_covering_proof(self, key: str) -> dict:
        blocks = self._proof_for_key(key)
        blocks.update(self._proof_for_left_sib(key))
        blocks.update(self._proof_for_right_sib(key))
        return blocks

    def _with_self(self, blocks: dict) -> dict:
        cid, raw = self.serialize()
        blocks[cid] = raw
        return blocks

    def _proof_for_key(self, key: str) -> dict:
        index = self.find_gt_or_equal_leaf_index(key)
        found = self.at_index(index)
        if found is not None and found.is_leaf() and found.key == key:
            blocks = {}
        else:
            prev = self.at_index(index - 1)
            if prev is None or prev.is_leaf():
                return {}
            blocks = prev._proof_for_key(key)
        return self._with_self(blocks)

    def _proof_for_left_sib(self, key: str) -> dict:
        index = self.find_gt_or_equal_leaf_index(key)
        prev = self.at_index(index - 1)
        blocks = {} if prev is None or prev.is_leaf() else prev._proof_for_left_sib(key)
        return self._with_self(blocks)

    def _proof_for_right_sib(self, key: str) -> dict:
        index = self.find_gt_or_equal_leaf_index(key)
        found = self.at_index(index)
        if found is None:
            found = self.at_index(index - 1)
        if found is None:
            blocks = {}
        elif found.is_tree():
            blocks = found._proof_for_right_sib(key)
        else:
            node = self.at_index(index + 1) if found.key == key else self.at_index(index - 1)
            blocks = {} if node is None or node.is_leaf() else node._proof_for_right_sib(key)
        return self._with_self(blocks)


def _layer_for_entries(entries: list) -> int | None:
    for entry in entries:
        if entry.is_leaf():
            return leading_zeros_on_hash(entry.key)
    return None


def _deserialize_node_data(storage, data: dict, layer: int | None) -> list:
    child_layer = layer - 1 if layer else None
    entries = []
    if data["l"] is not None:
        entries.append(MST.load(storage, data["l"], child_layer))
    last_key = ""
    for entry in data["e"]:
        key = last_key[: entry["p"]] + entry["k"].decode("ascii")
        ensure_valid_mst_key(key)
        entries.append(Leaf(key, entry["v"]))
        last_key = key
        if entry["t"] is not None:
            entries.append(MST.load(storage, entry["t"], child_layer))
    return entries
