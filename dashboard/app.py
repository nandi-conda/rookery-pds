# Roost dashboard: a read-only view of this PDS over its public XRPC API.
# Written for ultra (LPython -> wasm); see dashboard/README.md to build.

from lpython import i32, Const
from numpy import empty, int32
from ultra import (el, end, text, text_ref, num, cls, cls_if, attr, attr_ref, key,
                   value_ref, on_click, on_input, div, span, h1, after,
                   s_new, s_set, s_add, s_add_ref, s_copy, s_has, s_len,
                   http_get_ref, j_ok, j_err, j_free, j_at, j_idx, j_len,
                   j_int, j_str, j_has)

# ---- dashboard-specific imports (public/dashboard/rookery.js)

@jscall
def pds_base(dst: i32) -> None:
    """Write the PDS origin (e.g. https://rookery.latha.org) into dst."""
    pass

@jscall
def tid_secs(h: i32) -> i32:
    """Unix seconds encoded in the TID in string handle h, 0 if not a TID."""
    pass

@jscall
def ago(secs: i32) -> None:
    """Text node like '4m ago' for a unix time."""
    pass

@jscall
def date_text(h: i32) -> None:
    """Text node with an ISO date from h, shown relative to now."""
    pass

# ---- Msg
GOT_SERVER: Const[i32] = 1
GOT_REPOS: Const[i32] = 2
GOT_DESC: Const[i32] = 3
GOT_AGENTS: Const[i32] = 4
GOT_PROCS: Const[i32] = 5
GOT_RECORDS: Const[i32] = 6
TAB: Const[i32] = 7
SELECT: Const[i32] = 8
SELECT_COLL: Const[i32] = 9
FILTER: Const[i32] = 10
REFRESH: Const[i32] = 11
TICK: Const[i32] = 12
CLOSE: Const[i32] = 13
MORE: Const[i32] = 14
CLEAR_FILTER: Const[i32] = 15

T_ACCOUNTS: Const[i32] = 0
T_AGENTS: Const[i32] = 1
T_PROCS: Const[i32] = 2

CAP: Const[i32] = 1000
PAGE: Const[i32] = 100
REFRESH_MS: Const[i32] = 30000

# ---- Model
# Accounts as parallel columns: string handles for did/handle/rev, a JSON
# handle for each describeRepo response, and a recency order.
dids: i32[1000] = empty(1000, dtype=int32)
handles: i32[1000] = empty(1000, dtype=int32)
revs: i32[1000] = empty(1000, dtype=int32)
active: i32[1000] = empty(1000, dtype=int32)
descs: i32[1000] = empty(1000, dtype=int32)
when: i32[1000] = empty(1000, dtype=int32)
order: i32[1000] = empty(1000, dtype=int32)
n: i32 = 0

base: i32 = 0
url: i32 = 0
cursor: i32 = 0
tmp: i32 = 0
tmp2: i32 = 0
query: i32 = 0
err: i32 = 0

server: i32 = 0
agents: i32 = 0
procs: i32 = 0
records: i32 = 0
loading: i32 = 0
failed: i32 = 0
tab: i32 = 0
sel: i32 = -1
coll: i32 = 0
coll_i: i32 = -1
rec_cursor: i32 = 0
updated: i32 = 0


def init() -> None:
    global base, url, cursor, tmp, tmp2, query, err, coll, rec_cursor
    base = s_new()
    url = s_new()
    cursor = s_new()
    tmp = s_new()
    tmp2 = s_new()
    query = s_new()
    err = s_new()
    coll = s_new()
    rec_cursor = s_new()
    i: i32
    for i in range(CAP):
        dids[i] = s_new()
        handles[i] = s_new()
        revs[i] = s_new()
    pds_base(base)
    load_all()
    after(REFRESH_MS, TICK, 0)


def xrpc(method: str) -> None:
    """url = base + /xrpc/ + method; callers append the query string."""
    s_copy(url, base)
    s_add(url, "/xrpc/")
    s_add(url, method)


def load_all() -> None:
    ign: i32
    global server, agents, procs, loading, failed, n
    loading = 1
    failed = 0
    xrpc("com.atproto.server.describeServer")
    server = http_get_ref(url, GOT_SERVER)
    xrpc("com.atproto.sync.listRepos?limit=100")
    ign = http_get_ref(url, GOT_REPOS)
    xrpc("org.latha.agentbus.listAgents?limit=100")
    agents = http_get_ref(url, GOT_AGENTS)
    xrpc("org.latha.agentbus.listProcs?limit=100")
    procs = http_get_ref(url, GOT_PROCS)


def find_did(h: i32) -> i32:
    i: i32
    for i in range(n):
        if s_has(dids[i], h) == 1 and s_len(dids[i]) == s_len(h):
            return i
    return -1


def got_repos(doc: i32) -> None:
    ign: i32
    global n, loading, failed
    count: i32
    i: i32
    at: i32
    if j_ok(doc) == 0:
        j_err(doc, err)
        failed = 1
        loading = 0
        j_free(doc)
        return
    count = j_len(doc, "repos")
    for i in range(count):
        repo_field(doc, i, "did", tmp)
        at = find_did(tmp)
        if at < 0 and n < CAP:
            at = n
            n += 1
            s_copy(dids[at], tmp)
            descs[at] = 0
            order[at] = at
        if at >= 0:
            repo_field(doc, i, "rev", revs[at])
            when[at] = tid_secs(revs[at])
            active[at] = repo_active(doc, i)
            request_desc(at)
    if count == PAGE and j_str(doc, "cursor", cursor) == 1:
        xrpc("com.atproto.sync.listRepos?limit=100&cursor=")
        s_add_ref(url, cursor)
        ign = http_get_ref(url, GOT_REPOS)
    else:
        loading = 0
    j_free(doc)
    sort_by_recent()


def repo_field(doc: i32, i: i32, field: str, dst: i32) -> None:
    ign: i32
    item: i32 = j_idx_repo(doc, i)
    ign = j_str(item, field, dst)
    j_free(item)


def repo_active(doc: i32, i: i32) -> i32:
    item: i32 = j_idx_repo(doc, i)
    r: i32 = 1
    if j_has(item, "active") == 1:
        r = j_int(item, "active")
    j_free(item)
    return r


def j_idx_repo(doc: i32, i: i32) -> i32:
    arr: i32 = j_at(doc, "repos")
    item: i32 = j_idx(arr, i)
    j_free(arr)
    return item


def request_desc(i: i32) -> None:
    xrpc("com.atproto.repo.describeRepo?repo=")
    s_add_ref(url, dids[i])
    if descs[i] > 0:
        j_free(descs[i])
    descs[i] = http_get_ref(url, GOT_DESC)


def got_desc(doc: i32) -> None:
    ign: i32
    i: i32
    for i in range(n):
        if descs[i] == doc:
            if j_ok(doc) == 1:
                ign = j_str(doc, "handle", handles[i])


def sort_by_recent() -> None:
    i: i32
    j: i32
    v: i32
    for i in range(n):
        order[i] = i
    for i in range(1, n):
        v = order[i]
        j = i - 1
        while j >= 0 and when[order[j]] < when[v]:
            order[j + 1] = order[j]
            j -= 1
        order[j + 1] = v


def load_records() -> None:
    global records
    xrpc("com.atproto.repo.listRecords?limit=25&repo=")
    s_add_ref(url, dids[sel])
    s_add(url, "&collection=")
    s_add_ref(url, coll)
    if s_len(rec_cursor) > 0:
        s_add(url, "&cursor=")
        s_add_ref(url, rec_cursor)
    if records > 0:
        j_free(records)
    records = http_get_ref(url, GOT_RECORDS)


# ---- Update
def update(msg: i32, arg: i32) -> None:
    ign: i32
    global tab, sel, coll_i, records, updated
    if msg == GOT_SERVER:
        updated += 1
    elif msg == GOT_REPOS:
        got_repos(arg)
    elif msg == GOT_DESC:
        got_desc(arg)
    elif msg == TAB:
        tab = arg
    elif msg == SELECT:
        if sel == arg:
            sel = -1
        else:
            sel = arg
        coll_i = -1
        if records > 0:
            j_free(records)
        records = 0
    elif msg == SELECT_COLL:
        coll_i = arg
        coll_path(arg)
        s_set(rec_cursor, "")
        load_records()
    elif msg == MORE:
        ign = j_str(records, "cursor", rec_cursor)
        load_records()
    elif msg == CLOSE:
        sel = -1
        coll_i = -1
    elif msg == FILTER:
        s_copy(query, arg)
    elif msg == CLEAR_FILTER:
        s_set(query, "")
    elif msg == REFRESH:
        refresh()
    elif msg == TICK:
        refresh()
        after(REFRESH_MS, TICK, 0)


def coll_path(i: i32) -> None:
    ign: i32
    arr: i32 = j_at(descs[sel], "collections")
    item: i32 = j_idx(arr, i)
    ign = j_str(item, "", coll)
    j_free(item)
    j_free(arr)


def refresh() -> None:
    global server, agents, procs
    if loading == 1:
        return
    j_free(server)
    j_free(agents)
    j_free(procs)
    load_all()


# ---- View helpers
def item_str(doc: i32, list: str, i: i32, field: str, dst: i32) -> i32:
    arr: i32 = j_at(doc, list)
    item: i32 = j_idx(arr, i)
    r: i32 = j_str(item, field, dst)
    j_free(item)
    j_free(arr)
    return r


def stat(label: str, value: i32) -> None:
    div("stat")
    span("stat-value")
    num(value)
    end()
    span("stat-label")
    text(label)
    end()
    end()


def tab_button(label: str, which: i32, count: i32) -> None:
    el("button")
    cls("tab")
    cls_if("on", tab == which)
    attr("role", "tab")
    on_click(TAB, which)
    text(label)
    span("tab-count")
    num(count)
    end()
    end()


def link_ref(h: i32, label_h: i32) -> None:
    el("a")
    attr_ref("href", h)
    attr("target", "_blank")
    attr("rel", "noopener")
    text_ref(label_h)
    end()


def pdsls(dst: i32, what: i32) -> None:
    s_set(dst, "https://pdsls.dev/at://")
    s_add_ref(dst, what)


def chips(item: i32, path: str, field: str) -> None:
    """A chip for each entry of the array at path (or entry.field if given)."""
    ign: i32
    arr: i32 = j_at(item, path)
    count: i32 = j_len(arr, "")
    i: i32
    e: i32
    if count == 0:
        j_free(arr)
        return
    div("chips")
    for i in range(count):
        e = j_idx(arr, i)
        ign = j_str(e, field, tmp2)
        span("chip")
        text_ref(tmp2)
        end()
        j_free(e)
    end()
    j_free(arr)


def latest() -> i32:
    i: i32
    m: i32 = 0
    for i in range(n):
        if when[i] > m:
            m = when[i]
    return m


def active_count() -> i32:
    i: i32
    c: i32 = 0
    for i in range(n):
        c += active[i]
    return c


def collection_total() -> i32:
    i: i32
    c: i32 = 0
    for i in range(n):
        if descs[i] > 0:
            c += j_len(descs[i], "collections")
    return c


def matches(i: i32) -> bool:
    if s_len(query) == 0:
        return True
    return s_has(handles[i], query) == 1 or s_has(dids[i], query) == 1


# ---- View
def view_header() -> None:
    ign: i32
    el("header")
    cls("top")
    div("brand")
    pds_base(tmp)
    s_add(tmp, "/")
    el("a")
    cls("home")
    attr_ref("href", tmp)
    attr("aria-label", "Roost home")
    el("img")
    attr("src", "rookery-icon.svg")
    attr("alt", "")
    attr("width", "36")
    attr("height", "36")
    end()
    end()
    el("div")
    h1("Roost")
    el("p")
    cls("sub")
    if j_ok(server) == 1:
        ign = j_str(server, "did", tmp)
        text_ref(tmp)
        text(" · ")
        ign = j_str(server, "availableUserDomains.0", tmp)
        text("*.")
        text_ref(tmp)
    else:
        text("PDS dashboard")
    end()
    end()
    end()
    div("actions")
    el("span")
    cls("live")
    cls_if("busy", loading == 1)
    if loading == 1:
        text("Loading…")
    else:
        text("Live · refreshes every 30s")
    end()
    el("button")
    cls("ghost")
    on_click(REFRESH, 0)
    text("Refresh")
    end()
    pds_base(tmp)
    s_add(tmp, "/join")
    el("a")
    cls("signup")
    attr_ref("href", tmp)
    text("Sign up")
    end()
    end()
    end()


def view_stats() -> None:
    div("stats")
    if j_ok(server) == 1:
        stat("accounts", j_int(server, "accounts"))
    else:
        stat("accounts", n)
    stat("active repos", active_count())
    stat("collections", collection_total())
    stat("agents", j_len(agents, "agents"))
    stat("procs", j_len(procs, "procs"))
    div("stat")
    span("stat-value")
    if latest() > 0:
        ago(latest())
    else:
        text("—")
    end()
    span("stat-label")
    text("last commit")
    end()
    end()
    end()


def view_detail(i: i32) -> None:
    ign: i32
    count: i32
    c: i32
    r: i32
    item: i32
    arr: i32
    el("tr")
    cls("detail")
    key(-1 - i)
    el("td")
    attr("colspan", "4")
    div("detail-body")

    div("detail-head")
    el("code")
    text_ref(dids[i])
    end()
    pdsls(tmp, dids[i])
    s_set(tmp2, "Open in pdsls ↗")
    link_ref(tmp, tmp2)
    end()

    if j_has(descs[i], "__error") == 1:
        j_err(descs[i], tmp)
        el("p")
        cls("error")
        text_ref(tmp)
        end()
    elif j_ok(descs[i]) == 0:
        el("p")
        cls("muted")
        text("Loading repo…")
        end()
    else:
        count = j_len(descs[i], "collections")
        if count == 0:
            el("p")
            cls("muted")
            text("No records yet.")
            end()
        el("div")
        cls("chips")
        cls_if("hidden", count == 0)
        for c in range(count):
            ign = item_str(descs[i], "collections", c, "", tmp)
            el("button")
            cls("chip")
            cls_if("on", coll_i == c)
            on_click(SELECT_COLL, c)
            text_ref(tmp)
            end()
        end()

    if coll_i >= 0:
        view_records()

    end()
    end()
    end()


def view_records() -> None:
    ign: i32
    count: i32
    r: i32
    if records == 0 or (j_ok(records) == 0 and j_has(records, "__error") == 0):
        el("p")
        cls("muted")
        text("Loading records…")
        end()
        return
    if j_ok(records) == 0:
        j_err(records, tmp)
        el("p")
        cls("error")
        text_ref(tmp)
        end()
        return
    count = j_len(records, "records")
    el("ol")
    cls("records")
    for r in range(count):
        el("li")
        ign = item_str(records, "records", r, "uri", tmp)
        div("rec-head")
        el("code")
        text_ref(tmp)
        end()
        pdsls(tmp2, tmp)
        s_set(tmp, "view ↗")
        link_ref(tmp2, tmp)
        end()
        ign = item_str(records, "records", r, "value", tmp)
        el("pre")
        text_ref(tmp)
        end()
        end()
    end()
    if count == 0:
        el("p")
        cls("muted")
        text("Empty collection.")
        end()
    if j_has(records, "cursor") == 1 and count == 25:
        el("button")
        cls("ghost")
        on_click(MORE, 0)
        text("Next 25 →")
        end()


def view_accounts() -> None:
    k: i32
    i: i32
    shown: i32 = 0
    div("toolbar")
    el("input")
    cls("search")
    attr("type", "search")
    attr("placeholder", "Filter by handle or DID")
    attr("aria-label", "Filter accounts")
    value_ref(query)
    on_input(FILTER)
    end()
    end()

    if failed == 1:
        el("p")
        cls("error")
        text("Couldn't list repos: ")
        text_ref(err)
        end()

    el("table")
    cls("accounts")
    el("thead")
    el("tr")
    el("th")
    text("Handle")
    end()
    el("th")
    cls("hide-sm")
    text("DID")
    end()
    el("th")
    text("Last commit")
    end()
    el("th")
    cls("num")
    text("Collections")
    end()
    end()
    end()
    el("tbody")
    for k in range(n):
        i = order[k]
        if matches(i):
            shown += 1
            el("tr")
            key(i + 1)
            cls("row")
            cls_if("on", sel == i)
            cls_if("inactive", active[i] == 0)
            on_click(SELECT, i)
            el("td")
            cls("handle")
            if s_len(handles[i]) > 0:
                text_ref(handles[i])
            else:
                span("muted")
                text("resolving…")
                end()
            if active[i] == 0:
                span("badge")
                text("inactive")
                end()
            end()
            el("td")
            cls("did hide-sm")
            text_ref(dids[i])
            end()
            el("td")
            if when[i] > 0:
                ago(when[i])
            else:
                text("—")
            end()
            el("td")
            cls("num")
            if descs[i] > 0:
                num(j_len(descs[i], "collections"))
            end()
            end()
            if sel == i:
                view_detail(i)
    end()
    end()
    if shown == 0 and loading == 0:
        el("p")
        cls("muted")
        text("No accounts match.")
        end()


def view_agents() -> None:
    ign: i32
    count: i32 = j_len(agents, "agents")
    i: i32
    item: i32
    arr: i32
    if count == 0:
        el("p")
        cls("empty")
        text("No agents have published an org.latha.agentbus.agent record yet.")
        end()
        return
    el("ul")
    cls("cards")
    arr = j_at(agents, "agents")
    for i in range(count):
        item = j_idx(arr, i)
        el("li")
        cls("card")
        div("card-head")
        el("strong")
        ign = j_str(item, "name", tmp)
        text_ref(tmp)
        end()
        span("muted")
        ign = j_str(item, "handle", tmp)
        text_ref(tmp)
        end()
        end()
        if j_str(item, "value.description", tmp) == 1:
            el("p")
            text_ref(tmp)
            end()
        chips(item, "value.capabilities", "")
        chips(item, "value.taskClasses", "")
        el("p")
        cls("muted small")
        text("indexed ")
        ign = j_str(item, "indexedAt", tmp)
        date_text(tmp)
        end()
        end()
        j_free(item)
    j_free(arr)
    end()


def view_procs() -> None:
    ign: i32
    count: i32 = j_len(procs, "procs")
    i: i32
    item: i32
    arr: i32
    if count == 0:
        el("p")
        cls("empty")
        text("No procs have published an org.latha.agentbus.proc record yet.")
        end()
        return
    el("ul")
    cls("cards")
    arr = j_at(procs, "procs")
    for i in range(count):
        item = j_idx(arr, i)
        el("li")
        cls("card")
        div("card-head")
        el("strong")
        ign = j_str(item, "name", tmp)
        text_ref(tmp)
        end()
        span("muted")
        ign = j_str(item, "handle", tmp)
        text_ref(tmp)
        end()
        end()
        if j_str(item, "value.description", tmp) == 1:
            el("p")
            text_ref(tmp)
            end()
        chips(item, "value.provides", "function")
        chips(item, "value.publishes", "topic")
        end()
        j_free(item)
    j_free(arr)
    end()


def view() -> None:
    div("shell")
    view_header()
    view_stats()
    el("nav")
    cls("tabs")
    attr("role", "tablist")
    tab_button("Accounts", T_ACCOUNTS, n)
    tab_button("Agents", T_AGENTS, j_len(agents, "agents"))
    tab_button("Procs", T_PROCS, j_len(procs, "procs"))
    end()
    el("section")
    cls("panel")
    if tab == T_ACCOUNTS:
        view_accounts()
    elif tab == T_AGENTS:
        view_agents()
    else:
        view_procs()
    end()
    el("footer")
    text("Read-only view of public XRPC · built with ")
    el("a")
    attr("href", "https://github.com/codegod100/ultra")
    text("ultra")
    end()
    text(" (LPython → wasm)")
    end()
    end()
