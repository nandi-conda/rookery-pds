# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""agent-bus registry records, validated on write and indexed in D1.

- `org.latha.agentbus.agent`: an agent reachable over agent-bus, rkey == name.
- `org.latha.agentbus.proc`: a networked proc and the functions/topics it serves.
- `org.latha.agentbus.<service>` (rkey `self`): an XRPC service provider;
  validated but not indexed (brokers find them via listReposByCollection).

roost is lexicon-agnostic for every other collection.
"""

import json
import re
from datetime import datetime

from .urls import parse_url

AGENT_COLLECTION = "org.latha.agentbus.agent"
PROC_COLLECTION = "org.latha.agentbus.proc"
DELETE_TYPE = "com.atproto.repo.applyWrites#delete"

AGENTS_SCHEMA = """CREATE TABLE IF NOT EXISTS agentbus_agents (
  did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  task_classes TEXT NOT NULL,
  record TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (did, rkey)
)"""
PROCS_SCHEMA = """CREATE TABLE IF NOT EXISTS agentbus_procs (
  did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  functions TEXT NOT NULL,
  topics TEXT NOT NULL,
  record TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (did, rkey)
)"""

# A D-Bus bus name element without '-', so it is also a valid object path element.
AGENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
# Function and topic names: dotted app-domain words, e.g. weather.current.
BUS_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*)*$")
SERVICE_NSID_RE = re.compile(r"^org\.latha\.agentbus(\.[a-z][A-Za-z0-9]{0,62})+$")
METHOD_NAME_RE = re.compile(r"^[a-z][A-Za-z0-9]{0,62}$")
SERVICE_RKEY = "self"
MAX_LIST_ITEMS = 64
MAX_TAG_LENGTH = 256
MAX_TEXT_LENGTH = 2048
MAX_RECORD_BYTES = 64 * 1024
MAX_ENDPOINT_LENGTH = 512
LIST_DEFAULT_LIMIT = 50
LIST_MAX_LIMIT = 100


class InvalidAgentRecordError(ValueError):
    pass


def _js_len(text: str) -> int:
    """String length as JavaScript counts it (UTF-16 code units)."""
    return len(text.encode("utf-16-le")) // 2


def _json_bytes(value) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def is_datetime(value) -> bool:
    """Close to `!isNaN(Date.parse(value))` for the ISO 8601 forms agents send."""
    if not isinstance(value, str) or not value:
        return False
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        datetime.fromisoformat(text)
        return True
    except ValueError:
        return False


def _optional_text(record: dict, field: str, max_len: int, fail) -> None:
    if field not in record:
        return
    value = record[field]
    if not isinstance(value, str) or not value or _js_len(value) > max_len:
        fail(f"{field} must be a non-empty string of at most {max_len} characters")


def _optional_tag_list(record: dict, field: str, fail) -> None:
    if field not in record:
        return
    value = record[field]
    if (
        not isinstance(value, list) or len(value) > MAX_LIST_ITEMS
        or not all(isinstance(tag, str) and tag and _js_len(tag) <= MAX_TAG_LENGTH for tag in value)
    ):
        fail(f"{field} must be an array of at most {MAX_LIST_ITEMS} non-empty strings")


def _failer(prefix: str):
    def fail(message: str):
        raise InvalidAgentRecordError(f"Invalid {prefix} record: {message}")
    return fail


def _check_common(record, rkey, collection, fail, name_message) -> dict:
    if not isinstance(record, dict):
        fail("record must be an object")
    if _json_bytes(record) > MAX_RECORD_BYTES:
        fail(f"record exceeds {MAX_RECORD_BYTES} bytes")
    if "$type" in record and record["$type"] != collection:
        fail(f"$type must be {collection}")
    if not isinstance(record.get("name"), str) or not AGENT_NAME_RE.match(record["name"]):
        fail(name_message)
    if rkey != record["name"]:
        fail("rkey must equal name")
    if not is_datetime(record.get("createdAt")):
        fail("createdAt must be a datetime string")
    return record


def validate_agent_record(rkey: str | None, record) -> dict:
    fail = _failer(AGENT_COLLECTION)
    r = _check_common(record, rkey, AGENT_COLLECTION, fail,
                      "name must match [A-Za-z_][A-Za-z0-9_]{0,63} (a D-Bus name element)")
    _optional_text(r, "description", MAX_TEXT_LENGTH, fail)
    _optional_text(r, "endpoint", 512, fail)
    for field in ("capabilities", "taskClasses", "interfaces"):
        _optional_tag_list(r, field, fail)
    if "transportKey" in r:
        _optional_text(r, "transportKey", 512, fail)
        if not r["transportKey"].startswith("did:key:"):
            fail("transportKey must be a did:key")
    if "freeq" in r:
        freeq = r["freeq"]
        if not isinstance(freeq, dict):
            fail("freeq must be an object")
        server = freeq.get("server")
        if not isinstance(server, str) or not server or _js_len(server) > 256:
            fail("freeq.server must be a non-empty string")
        _optional_text(freeq, "channel", 256, fail)
        if "did" in freeq and (not isinstance(freeq["did"], str) or not freeq["did"].startswith("did:")):
            fail("freeq.did must be a DID")
    return r


def _entry_list(record: dict, field: str, key: str, fail) -> None:
    if field not in record:
        return
    value = record[field]
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        fail(f"{field} must be an array of at most {MAX_LIST_ITEMS} entries")
    for entry in value:
        if not isinstance(entry, dict):
            fail(f"{field} entries must be objects")
        name = entry.get(key)
        if not isinstance(name, str) or _js_len(name) > MAX_TAG_LENGTH or not BUS_NAME_RE.match(name):
            fail(f"{field}[].{key} must be a dotted name such as weather.current")
        try:
            _optional_tag_list(entry, "regions", fail)
            _optional_text(entry, "subjects", MAX_TAG_LENGTH, fail)
        except InvalidAgentRecordError:
            fail(f"{field}[] has a malformed regions or subjects field")


def validate_proc_record(rkey: str | None, record) -> dict:
    fail = _failer(PROC_COLLECTION)
    r = _check_common(record, rkey, PROC_COLLECTION, fail, "name must match [A-Za-z_][A-Za-z0-9_]{0,63}")
    try:
        _optional_text(r, "description", MAX_TEXT_LENGTH, fail)
    except InvalidAgentRecordError:
        fail(f"description must be a non-empty string of at most {MAX_TEXT_LENGTH} characters")
    _entry_list(r, "provides", "function", fail)
    _entry_list(r, "publishes", "topic", fail)
    if "freeq" in r:
        freeq = r["freeq"]
        ok = (
            isinstance(freeq, dict)
            and isinstance(freeq.get("server"), str) and 0 < _js_len(freeq["server"]) <= 256
            and ("channel" not in freeq or (isinstance(freeq["channel"], str) and _js_len(freeq["channel"]) <= 256))
            and ("did" not in freeq or (isinstance(freeq["did"], str) and freeq["did"].startswith("did:")))
        )
        if not ok:
            fail("freeq must be {server, channel?, did?}")
    return r


def _collect(writes: list, collection: str, validate, fail) -> list[dict]:
    out = []
    for write in writes:
        if write.get("collection") != collection:
            continue
        if write.get("$type") == DELETE_TYPE:
            if not write.get("rkey"):
                fail("delete requires rkey")
            out.append({"kind": "delete", "rkey": write["rkey"]})
        else:
            out.append({"kind": "put", "rkey": write.get("rkey"), "record": validate(write.get("rkey"), write.get("value"))})
    return out


def collect_agent_writes(writes: list) -> list[dict]:
    """Validate the agent writes in a batch before commit; returns index updates."""
    return _collect(writes, AGENT_COLLECTION, validate_agent_record, _failer(AGENT_COLLECTION))


def collect_proc_writes(writes: list) -> list[dict]:
    return _collect(writes, PROC_COLLECTION, validate_proc_record, _failer(PROC_COLLECTION))


def _dumps(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


async def apply_agent_index(db, did: str, writes: list[dict]) -> None:
    if not writes:
        return
    await db.run(AGENTS_SCHEMA)
    await db.batch([
        ("DELETE FROM agentbus_agents WHERE did = ? AND rkey = ?", [did, write["rkey"]])
        if write["kind"] == "delete" else (
            """INSERT INTO agentbus_agents (did, rkey, capabilities, task_classes, record, indexed_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT (did, rkey) DO UPDATE SET
                 capabilities = excluded.capabilities,
                 task_classes = excluded.task_classes,
                 record = excluded.record,
                 indexed_at = excluded.indexed_at""",
            [did, write["rkey"], _dumps(write["record"].get("capabilities", [])),
             _dumps(write["record"].get("taskClasses", [])), _dumps(write["record"])],
        )
        for write in writes
    ])


async def apply_proc_index(db, did: str, writes: list[dict]) -> None:
    if not writes:
        return
    await db.run(PROCS_SCHEMA)
    await db.batch([
        ("DELETE FROM agentbus_procs WHERE did = ? AND rkey = ?", [did, write["rkey"]])
        if write["kind"] == "delete" else (
            """INSERT INTO agentbus_procs (did, rkey, functions, topics, record, indexed_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT (did, rkey) DO UPDATE SET
                 functions = excluded.functions,
                 topics = excluded.topics,
                 record = excluded.record,
                 indexed_at = excluded.indexed_at""",
            [did, write["rkey"],
             _dumps([entry["function"] for entry in write["record"].get("provides", [])]),
             _dumps([entry["topic"] for entry in write["record"].get("publishes", [])]),
             _dumps(write["record"])],
        )
        for write in writes
    ])


async def delete_agents_for_did(db, did: str) -> None:
    await db.run(AGENTS_SCHEMA)
    await db.run("DELETE FROM agentbus_agents WHERE did = ?", did)


async def delete_procs_for_did(db, did: str) -> None:
    await db.run(PROCS_SCHEMA)
    await db.run("DELETE FROM agentbus_procs WHERE did = ?", did)


def clamp_list_limit(raw: str | None) -> int | None:
    """Default 50, max 100; None for a value that isn't a positive integer."""
    if raw is None:
        return LIST_DEFAULT_LIMIT
    try:
        number = float(raw.strip()) if raw.strip() else 0.0
    except ValueError:
        return None
    if not number.is_integer() or number < 1:
        return None
    return min(int(number), LIST_MAX_LIMIT)


def encode_cursor(did: str, name: str) -> str:
    return f"{did}/{name}"


def decode_cursor(raw: str) -> dict | None:
    slash = raw.rfind("/")
    if slash <= 0 or slash == len(raw) - 1:
        return None
    return {"did": raw[:slash], "rkey": raw[slash + 1:]}


async def _list(db, schema, table, collection, filters: list[tuple[str, str | None]], did, cursor, limit):
    await db.run(schema)
    where, binds = ["a.active = 1"], []
    if did:
        where.append("g.did = ?")
        binds.append(did)
    for column, value in filters:
        if value:
            where.append(f"EXISTS (SELECT 1 FROM json_each(g.{column}) WHERE value = ?)")
            binds.append(value)
    if cursor:
        where.append("(g.did > ? OR (g.did = ? AND g.rkey > ?))")
        binds += [cursor["did"], cursor["did"], cursor["rkey"]]
    rows = await db.all(
        f"""SELECT g.did, g.rkey, g.record, g.indexed_at, a.handle
            FROM {table} g JOIN accounts a ON a.did = g.did
            WHERE {' AND '.join(where)}
            ORDER BY g.did, g.rkey
            LIMIT ?""",
        *binds, limit,
    )
    return [
        {
            "uri": f"at://{row['did']}/{collection}/{row['rkey']}",
            "did": row["did"],
            "handle": row["handle"],
            "name": row["rkey"],
            "value": json.loads(row["record"]),
            "indexedAt": row["indexed_at"],
        }
        for row in rows
    ]


async def list_agents(db, limit: int, did=None, capability=None, task_class=None, cursor=None) -> list[dict]:
    return await _list(db, AGENTS_SCHEMA, "agentbus_agents", AGENT_COLLECTION,
                       [("capabilities", capability), ("task_classes", task_class)], did, cursor, limit)


async def list_procs(db, limit: int, did=None, fn=None, topic=None, cursor=None) -> list[dict]:
    return await _list(db, PROCS_SCHEMA, "agentbus_procs", PROC_COLLECTION,
                       [("functions", fn), ("topics", topic)], did, cursor, limit)


def is_service_collection(collection: str) -> bool:
    return collection.startswith("org.latha.agentbus.") and collection not in (AGENT_COLLECTION, PROC_COLLECTION)


def _is_service_endpoint(value) -> bool:
    """https without credentials, query or fragment; plain http only on localhost."""
    if not isinstance(value, str) or _js_len(value) > MAX_ENDPOINT_LENGTH:
        return False
    try:
        url = parse_url(value)
    except ValueError:
        return False
    if url.username or url.password or url.search or url.hash:
        return False
    return url.protocol == "https:" or (url.protocol == "http:" and url.hostname in ("localhost", "127.0.0.1"))


def validate_service_record(collection: str, rkey: str | None, record) -> dict:
    fail = _failer(collection)
    if not SERVICE_NSID_RE.match(collection) or len(collection) > MAX_TAG_LENGTH:
        fail("collection must be org.latha.agentbus.<service>, e.g. org.latha.agentbus.weather")
    if rkey != SERVICE_RKEY:
        fail(f"rkey must be {SERVICE_RKEY}")
    if not isinstance(record, dict):
        fail("record must be an object")
    if _json_bytes(record) > MAX_RECORD_BYTES:
        fail(f"record exceeds {MAX_RECORD_BYTES} bytes")
    if "$type" in record and record["$type"] != collection:
        fail(f"$type must be {collection}")
    if not _is_service_endpoint(record.get("endpoint")):
        fail(f"endpoint must be an https URL of at most {MAX_ENDPOINT_LENGTH} characters, without query or fragment")
    methods = record.get("methods")
    if not isinstance(methods, list) or not methods or len(methods) > MAX_LIST_ITEMS:
        fail(f"methods must be a non-empty array of at most {MAX_LIST_ITEMS} NSIDs")
    for method in methods:
        if (
            not isinstance(method, str) or not method.startswith(f"{collection}.")
            or not METHOD_NAME_RE.match(method[len(collection) + 1:])
        ):
            fail(f"methods[] must be NSIDs directly under {collection}, e.g. {collection}.current")
    if not is_datetime(record.get("createdAt")):
        fail("createdAt must be a datetime string")
    return record


def check_service_writes(writes: list) -> None:
    for write in writes:
        if not is_service_collection(write.get("collection", "")) or write.get("$type") == DELETE_TYPE:
            continue
        validate_service_record(write["collection"], write.get("rkey"), write.get("value"))
