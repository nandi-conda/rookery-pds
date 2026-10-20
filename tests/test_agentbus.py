# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The agentbus registry: record validation, the D1 index behind listAgents and
listProcs, service provider records, and moving an account between hosts."""

import json

import pytest

from conftest import OPERATOR_TOKEN
from rookery import cbor
from rookery.agentbus import (
    InvalidAgentRecordError, validate_agent_record, validate_proc_record, validate_service_record,
)
from rookery.identity import build_unsigned_genesis_op

OPERATOR = {"authorization": f"Bearer {OPERATOR_TOKEN}"}
CREATED = "2026-01-01T00:00:00.000Z"


def agent_record(name: str, **extra) -> dict:
    record = {
        "$type": "org.latha.agentbus.agent",
        "name": name,
        "description": f"{name} agent",
        "capabilities": ["plan"],
        "taskClasses": ["org.latha.agentbus.task.plan"],
        "interfaces": ["org.latha.agentbus.Agent1"],
        "freeq": {"server": "irc.freeq.at", "channel": "#agentbus-test"},
        "createdAt": CREATED,
    }
    record.update(extra)
    return {key: value for key, value in record.items() if value is not None}


def proc_record(name: str, **extra) -> dict:
    record = {
        "$type": "org.latha.agentbus.proc",
        "name": name,
        "description": f"{name} proc",
        "provides": [{"function": "weather.current"}, {"function": "weather.forecast", "regions": ["EU"]}],
        "publishes": [{"topic": "weather.current", "subjects": "place"}, {"topic": "weather.alert", "subjects": "place"}],
        "freeq": {"server": "irc.freeq.at"},
        "createdAt": CREATED,
    }
    record.update(extra)
    return {key: value for key, value in record.items() if value is not None}


def service_record(**extra) -> dict:
    record = {
        "$type": "org.latha.agentbus.weather",
        "endpoint": "https://codegod100--agentbus-weather.modal.run",
        "methods": ["org.latha.agentbus.weather.current"],
        "createdAt": CREATED,
    }
    record.update(extra)
    return {key: value for key, value in record.items() if value is not None}


async def call(rook, method: str, body):
    return await rook.post(f"/xrpc/com.atproto.repo.{method}", body)


async def list_agents(client, **params):
    response = await client.get("/xrpc/org.latha.agentbus.listAgents", params=params)
    return response.status, response.json()


async def list_procs(client, **params):
    response = await client.get("/xrpc/org.latha.agentbus.listProcs", params=params)
    return response.status, response.json()


def names(body: dict, key: str = "agents") -> list[str]:
    return [entry["name"] for entry in body[key]]


# Validation

def test_accepts_a_well_formed_agent_record():
    assert validate_agent_record("planner", agent_record("planner"))["name"] == "planner"


@pytest.mark.parametrize("rkey,record", [
    ("other", agent_record("planner")),
    ("1planner", agent_record("1planner")),
    ("my-agent", agent_record("my-agent")),
    ("planner", {k: v for k, v in agent_record("planner").items() if k != "createdAt"}),
    ("planner", agent_record("planner", **{"$type": "org.latha.agentbus.other"})),
    ("planner", agent_record("planner", capabilities=[1])),
    ("planner", agent_record("planner", transportKey="abc")),
    ("planner", agent_record("planner", freeq={"channel": "#x"})),
    ("planner", []),
], ids=["rkey-mismatch", "digit-leading", "hyphenated", "no-createdAt", "wrong-type", "non-string-capability",
        "transportKey", "freeq-no-server", "array"])
def test_rejects_bad_agent_records(rkey, record):
    with pytest.raises(InvalidAgentRecordError):
        validate_agent_record(rkey, record)


def test_accepts_a_well_formed_proc_record():
    assert validate_proc_record("weather", proc_record("weather"))["name"] == "weather"


@pytest.mark.parametrize("rkey,record", [
    ("other", proc_record("weather")),
    ("weather", {k: v for k, v in proc_record("weather").items() if k != "createdAt"}),
    ("weather", proc_record("weather", **{"$type": "org.latha.agentbus.agent"})),
    ("weather", proc_record("weather", provides="weather.current")),
    ("weather", proc_record("weather", provides=[{"function": "weather current"}])),
    ("weather", proc_record("weather", publishes=[{"topic": "weather.*"}])),
    ("weather", proc_record("weather", provides=[{"function": "weather.current", "regions": [1]}])),
    ("weather", proc_record("weather", freeq={})),
], ids=["rkey-mismatch", "no-createdAt", "wrong-type", "provides-not-array", "function-spaces", "topic-pattern",
        "bad-regions", "freeq-no-server"])
def test_rejects_bad_proc_records(rkey, record):
    with pytest.raises(InvalidAgentRecordError):
        validate_proc_record(rkey, record)


def test_accepts_service_records_and_http_only_on_localhost():
    assert validate_service_record("org.latha.agentbus.weather", "self", service_record())["methods"] == [
        "org.latha.agentbus.weather.current"]
    assert validate_service_record("org.latha.agentbus.weather", "self", service_record(endpoint="http://localhost:8000"))


@pytest.mark.parametrize("collection,rkey,record", [
    ("org.latha.agentbus.weather", "weather", service_record()),
    ("org.latha.agentbus.Weather", "self", {k: v for k, v in service_record().items() if k != "$type"}),
    ("org.latha.agentbus.weather", "self", service_record(**{"$type": "org.latha.agentbus.files"})),
    ("org.latha.agentbus.weather", "self", service_record(endpoint="http://weather.example")),
    ("org.latha.agentbus.weather", "self", service_record(endpoint="https://w.example/?x=1")),
    ("org.latha.agentbus.weather", "self", service_record(methods=[])),
    ("org.latha.agentbus.weather", "self", service_record(methods=["org.latha.agentbus.files.list"])),
    ("org.latha.agentbus.weather", "self", service_record(methods=["org.latha.agentbus.weather.a.b"])),
    ("org.latha.agentbus.weather", "self", {k: v for k, v in service_record().items() if k != "createdAt"}),
], ids=["rkey-not-self", "uppercase-name", "wrong-type", "plain-http", "query", "no-methods", "foreign-method",
        "nested-method", "no-createdAt"])
def test_rejects_bad_service_records(collection, rkey, record):
    with pytest.raises(InvalidAgentRecordError):
        validate_service_record(collection, rkey, record)


# Agent registry

async def test_indexes_filters_updates_and_removes_agents(client, enroll):
    host = await enroll()
    collection = "org.latha.agentbus.agent"
    assert (await call(host, "putRecord", {"repo": host.did, "collection": collection, "rkey": "planner",
                                           "record": agent_record("planner")})).status == 200
    assert (await call(host, "createRecord", {"repo": host.did, "collection": collection, "rkey": "coder", "record": agent_record(
        "coder", capabilities=["code.review"], taskClasses=["org.latha.agentbus.task.code"])})).status == 200

    status, body = await list_agents(client, did=host.did)
    assert status == 200 and names(body) == ["coder", "planner"]
    planner = body["agents"][1]
    assert planner["uri"] == f"at://{host.did}/{collection}/planner" and planner["did"] == host.did
    assert planner["value"]["name"] == "planner" and planner["value"]["freeq"]["server"] == "irc.freeq.at"
    assert planner["handle"].endswith(".rookery.test")

    assert names((await list_agents(client, did=host.did, capability="code.review"))[1]) == ["coder"]
    assert names((await list_agents(client, did=host.did, taskClass="org.latha.agentbus.task.plan"))[1]) == ["planner"]

    assert (await call(host, "putRecord", {"repo": host.did, "collection": collection, "rkey": "planner",
                                           "record": agent_record("planner", capabilities=["plan", "code.review"])})).status == 200
    assert names((await list_agents(client, did=host.did, capability="code.review"))[1]) == ["coder", "planner"]

    assert (await call(host, "deleteRecord", {"repo": host.did, "collection": collection, "rkey": "coder"})).status == 200
    assert names((await list_agents(client, did=host.did))[1]) == ["planner"]


async def test_apply_writes_indexes_agents_atomically_with_validation(client, enroll):
    host = await enroll()
    create = "com.atproto.repo.applyWrites#create"
    collection = "org.latha.agentbus.agent"
    bad = await call(host, "applyWrites", {"repo": host.did, "writes": [
        {"$type": create, "collection": collection, "rkey": "a", "record": agent_record("a")},
        {"$type": create, "collection": collection, "rkey": "b", "record": agent_record("c")},
    ]})
    assert bad.status == 400 and bad.json()["error"] == "InvalidRecord"
    assert (await list_agents(client, did=host.did))[1]["agents"] == []

    good = await call(host, "applyWrites", {"repo": host.did, "writes": [
        {"$type": create, "collection": collection, "rkey": "a", "record": agent_record("a")},
        {"$type": create, "collection": collection, "rkey": "b", "record": agent_record("b")},
        {"$type": create, "collection": "com.example.other", "record": {"text": "untouched"}},
    ]})
    assert good.status == 200
    assert names((await list_agents(client, did=host.did))[1]) == ["a", "b"]

    await call(host, "applyWrites", {"repo": host.did, "writes": [
        {"$type": "com.atproto.repo.applyWrites#delete", "collection": collection, "rkey": "a"}]})
    assert names((await list_agents(client, did=host.did))[1]) == ["b"]


async def test_invalid_agent_records_are_not_written(client, enroll):
    host = await enroll()
    collection = "org.latha.agentbus.agent"
    no_rkey = await call(host, "createRecord", {"repo": host.did, "collection": collection, "record": agent_record("planner")})
    assert no_rkey.status == 400 and no_rkey.json()["error"] == "InvalidRecord"
    mismatch = await call(host, "putRecord", {"repo": host.did, "collection": collection, "rkey": "planner", "record": agent_record("coder")})
    assert mismatch.status == 400
    listed = await client.get("/xrpc/com.atproto.repo.listRecords", params={"repo": host.did, "collection": collection})
    assert listed.json()["records"] == []


async def test_agents_paginate_across_accounts_with_a_bounded_limit(client, enroll):
    one, two = await enroll(), await enroll()
    for host in (one, two):
        assert (await call(host, "putRecord", {"repo": host.did, "collection": "org.latha.agentbus.agent", "rkey": "pager",
                                               "record": agent_record("pager", capabilities=["pager.test"])})).status == 200
    _, first = await list_agents(client, capability="pager.test", limit="1")
    assert len(first["agents"]) == 1 and first["cursor"]
    _, second = await list_agents(client, capability="pager.test", limit="1", cursor=first["cursor"])
    assert len(second["agents"]) == 1
    assert {first["agents"][0]["did"], second["agents"][0]["did"]} == {one.did, two.did}
    assert (await list_agents(client, limit="0"))[0] == 400
    assert (await list_agents(client, cursor="nope"))[0] == 400


# Proc registry

async def test_indexes_filters_and_removes_procs(client, enroll):
    proc = await enroll()
    collection = "org.latha.agentbus.proc"
    assert (await call(proc, "putRecord", {"repo": proc.did, "collection": collection, "rkey": "weather",
                                           "record": proc_record("weather")})).status == 200
    status, body = await list_procs(client, did=proc.did)
    assert status == 200 and len(body["procs"]) == 1
    entry = body["procs"][0]
    assert entry["uri"] == f"at://{proc.did}/{collection}/weather" and entry["name"] == "weather"
    assert [p["topic"] for p in entry["value"]["publishes"]] == ["weather.current", "weather.alert"]
    assert names((await list_procs(client, did=proc.did, topic="weather.alert"))[1], "procs") == ["weather"]
    assert (await list_procs(client, did=proc.did, function="calendar.events"))[1]["procs"] == []

    bad = await call(proc, "putRecord", {"repo": proc.did, "collection": collection, "rkey": "weather",
                                         "record": proc_record("weather", publishes=[{"topic": ""}])})
    assert bad.status == 400 and bad.json()["error"] == "InvalidRecord"
    assert (await call(proc, "deleteRecord", {"repo": proc.did, "collection": collection, "rkey": "weather"})).status == 200
    assert (await list_procs(client, did=proc.did))[1]["procs"] == []
    assert (await list_procs(client, limit="0"))[0] == 400


# DID service and provider records

def test_genesis_op_carries_the_agentbus_service_only_when_configured():
    class Key:
        def did(self):
            return "did:key:zTest"
    assert "agentbus" not in build_unsigned_genesis_op("a.rookery.test", "rookery.test", Key(), Key())["services"]
    assert build_unsigned_genesis_op("a.rookery.test", "rookery.test", Key(), Key(), "ircs://irc.freeq.at:6697")["services"] == {
        "atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://rookery.test"},
        "agentbus": {"type": "AgentBusEndpoint", "endpoint": "ircs://irc.freeq.at:6697"},
    }


async def test_service_provider_records_are_validated(enroll):
    proc = await enroll()
    base = {"repo": proc.did, "collection": "org.latha.agentbus.weather", "rkey": "self"}
    assert (await call(proc, "putRecord", dict(base, record=service_record()))).status == 200
    bad = await call(proc, "putRecord", dict(base, record=service_record(endpoint="ftp://weather.example")))
    assert bad.status == 400 and bad.json()["error"] == "InvalidRecord"


# Moving an account between hosts

async def latest_commit(client, did: str) -> dict:
    return (await client.get("/xrpc/com.atproto.sync.getLatestCommit", params={"did": did})).json()


async def test_export_and_import_into_a_new_durable_object(client, env, enroll):
    proc = await enroll()
    assert (await call(proc, "putRecord", {"repo": proc.did, "collection": "org.latha.agentbus.proc", "rkey": "weather",
                                           "record": proc_record("weather")})).status == 200
    blob = (await call(proc, "uploadBlob", {"hello": "blob"})).json()["blob"]

    export = "/operator/account/export"
    assert (await client.get(export, params={"did": proc.did})).status == 403
    assert (await client.get(export, params={"did": proc.did}, headers={"authorization": "Bearer wrong"})).status == 403
    exported = await client.get(export, params={"did": proc.did}, headers=OPERATOR)
    assert exported.status == 200
    assert exported.headers["content-type"] == "application/cbor"
    before = await latest_commit(client, proc.did)

    await env.db.run("DELETE FROM accounts WHERE did = ?", proc.did)
    await env.db.run("DELETE FROM agentbus_procs WHERE did = ?", proc.did)
    assert (await list_procs(client, did=proc.did))[1]["procs"] == []

    imp = "/operator/account/import"
    assert (await client.post(imp, body=exported.body)).status == 403
    assert (await client.post(imp, body=b"nope", headers=OPERATOR)).status == 400
    imported = await client.post(imp, body=exported.body, headers=OPERATOR)
    assert imported.status == 200, imported.text
    assert {k: imported.json()[k] for k in ("did", "rev", "blobs", "agents", "procs")} == {
        "did": proc.did, "rev": before["rev"], "blobs": 1, "agents": 0, "procs": 1}
    assert (await client.post(imp, body=exported.body, headers=OPERATOR)).status == 409

    assert await latest_commit(client, proc.did) == before
    assert names((await list_procs(client, did=proc.did))[1], "procs") == ["weather"]
    got = await client.get("/xrpc/com.atproto.sync.getBlob", params={"did": proc.did, "cid": blob["ref"]["$link"]})
    assert got.status == 200 and json.loads(got.body) == {"hello": "blob"}

    moved = await call(proc, "putRecord", {"repo": proc.did, "collection": "org.latha.agentbus.proc", "rkey": "weather",
                                           "record": proc_record("weather", description="moved")})
    assert moved.status == 200
    assert (await latest_commit(client, proc.did))["rev"] > before["rev"]


async def test_identity_sync_repoints_the_did_and_keeps_the_handle(client, env, enroll):
    proc = await enroll()
    exported = cbor.decode((await client.get("/operator/account/export", params={"did": proc.did}, headers=OPERATOR)).body)
    state = exported["state"]
    env.plc.log[proc.did] = [{
        "did": proc.did, "cid": "bafyreigenesis", "nullified": False,
        "operation": {
            "type": "plc_operation", "rotationKeys": [f"did:key:{state['rotation_key_pub']}"], "verificationMethods": {},
            "alsoKnownAs": [f"at://{state['handle']}"],
            "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://old.example"}},
            "prev": None, "sig": "x",
        },
    }]
    synced = await client.post("/operator/identity/sync", json_body={"did": proc.did, "handle": state["handle"]}, headers=OPERATOR)
    assert synced.status == 200, synced.text
    posted = env.plc.log[proc.did][-1]["operation"]
    assert posted["alsoKnownAs"] == [f"at://{state['handle']}"]
    assert posted["services"]["atproto_pds"]["endpoint"] == "https://rookery.test"
