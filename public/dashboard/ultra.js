// ultra.js: the DOM glue for ultra apps written in LPython.
//
// The wasm module calls into the "js" imports below while view() runs; those
// calls build a lightweight vnode tree. After view() returns we diff the new
// tree against the last one and patch the DOM. Events are delegated from the
// mount point and turned into update(msg, arg) calls.

const EVENT = 0;

export async function mount(root, url, opts = {}) {
  if (typeof root === "string") root = document.querySelector(root);

  let mem, ex;
  const td = new TextDecoder();
  const cache = new Map();

  // LPython strings are a pointer to { data: i32, len: i32 }.
  // Literals live in static data, so decoding is cached by (data, len).
  let dv = null;
  const str = (p) => {
    if (dv === null || dv.buffer !== mem.buffer) dv = new DataView(mem.buffer);
    const a = dv.getInt32(p, true), l = dv.getInt32(p + 4, true);
    const k = a * 4096 + l;
    let s = cache.get(k);
    if (s === undefined) {
      s = td.decode(new Uint8Array(mem.buffer, a, l));
      if (l < 4096) cache.set(k, s);
    }
    return s;
  };

  const K = (k) => (typeof k === "object" ? k.k : str(k)); // storage key

  // ------------------------------------------------------------ string store
  const strs = [""];
  const free = [];
  const sNew = (v = "") => {
    if (free.length) { const h = free.pop(); strs[h] = v; return h; }
    strs.push(v); return strs.length - 1;
  };

  // ------------------------------------------------------------ vnode builder
  // vnode: { t, k, a, cls, p, ev, c, n }   text: { t: "#", s, n }
  let stack, cur;
  const node = (t) => ({ t, k: null, a: null, cls: "", p: null, ev: null, c: [], n: null });
  let nodes = 0;
  const push = (v) => { nodes++; cur.c.push(v); };
  const txt = (s) => push({ t: "#", k: null, s: String(s), n: null });
  const setA = (k, v) => ((cur.a ||= {})[k] = v);
  const setP = (k, v) => ((cur.p ||= {})[k] = v);
  const setEv = (k, v) => ((cur.ev ||= {})[k] = v);

  // ------------------------------------------------------------ scheduling
  // Messages are applied immediately; the re-render is batched onto the next
  // animation frame. frame(msg, arg) messages are held until that frame and
  // applied just before view(), so an animation steps once per rendered frame.
  let queued = false;
  let frameQ = [];
  let since = 0, tUpdate = 0; // first dispatch since the last render, time in update()
  const schedule = () => {
    if (queued) return;
    queued = true;
    if (!since) since = performance.now();
    requestAnimationFrame(render);
  };
  const dispatch = (msg, arg) => {
    const t = performance.now();
    if (!since) since = t;
    ex.update(msg, arg);
    tUpdate += performance.now() - t;
    schedule();
  };

  // ------------------------------------------------------------ json store
  // Decoded JSON values live here too; LPython holds i32 handles and reads
  // fields by dotted path ("repos.3.did"). Handle 0 is "nothing".
  const vals = [undefined];
  const vfree = [];
  const vNew = (v) => {
    if (v === undefined) return 0;
    if (vfree.length) { const h = vfree.pop(); vals[h] = v; return h; }
    vals.push(v); return vals.length - 1;
  };
  const walk = (h, p) => {
    let v = vals[h];
    const path = str(p);
    if (path) for (const k of path.split(".")) { if (v == null) return undefined; v = v[k]; }
    return v;
  };
  const asText = (v) => (typeof v === "string" ? v : JSON.stringify(v, null, 2));
  const httpGet = (url, msg) => {
    const h = vNew(null);
    fetch(url, { headers: { accept: "application/json" } })
      .then(async (r) => {
        const body = await r.json().catch(() => null);
        vals[h] = r.ok ? body
          : { __error: (body && (body.message || body.error)) || "HTTP " + r.status };
      })
      .catch((e) => { vals[h] = { __error: String(e.message || e) }; })
      .then(() => dispatch(msg, h));
    return h;
  };

  const js = {
    el: (p) => { const v = node(str(p)); push(v); stack.push(cur); cur = v; },
    end: () => { cur = stack.pop(); },
    text: (p) => txt(str(p)),
    num: (x) => txt(x),
    fnum: (x, d) => txt(x.toFixed(d)),
    text_ref: (h) => txt(strs[h] ?? ""),

    attr: (k, v) => setA(str(k), str(v)),
    attr_num: (k, v) => setA(str(k), String(v)),
    attr_ref: (k, h) => setA(str(k), strs[h] ?? ""),
    cls: (p) => { const c = str(p); if (c) cur.cls = cur.cls ? cur.cls + " " + c : c; },
    cls_if: (p, on) => { if (on) js.cls(p); },
    key: (k) => { cur.k = k; },
    value_ref: (h) => setP("value", strs[h] ?? ""),
    checked: (on) => setP("checked", !!on),
    autofocus: () => setP("__focus", true),

    on_click: (m, a) => setEv("click", [m, a]),
    on_dblclick: (m, a) => setEv("dblclick", [m, a]),
    on_input: (m) => setEv("input", [m, EVENT]),
    on_enter: (m, a) => setEv("enter", [m, a]),

    after: (ms, m, a) => setTimeout(() => dispatch(m, a), ms),
    frame: (m, a) => { frameQ.push(m, a); schedule(); },
    now_ms: () => performance.now(),
    log: (x) => console.log("[ultra]", x),

    s_new: () => sNew(),
    s_dup: (h) => sNew(strs[h]),
    s_copy: (d, s) => { strs[d] = strs[s]; },
    s_clear: (h) => { strs[h] = ""; },
    s_free: (h) => { if (h > 0) { strs[h] = ""; free.push(h); } },
    s_len: (h) => (strs[h] ?? "").trim().length,
    s_set: (h, p) => { strs[h] = str(p); },
    s_add: (h, p) => { strs[h] += str(p); },
    s_add_ref: (h, s) => { strs[h] += strs[s] ?? ""; },
    s_add_num: (h, x) => { strs[h] += String(x); },
    s_eq: (a, b) => (strs[a] === strs[b] ? 1 : 0),
    s_has: (h, n) => ((strs[h] ?? "").toLowerCase().includes((strs[n] ?? "").trim().toLowerCase()) ? 1 : 0),
    s_save: (k, h) => { try { localStorage.setItem(K(k), strs[h]); } catch {} },
    s_load: (k, h) => {
      let v = null;
      try { v = localStorage.getItem(K(k)); } catch {}
      if (v === null) return 0;
      strs[h] = v; return 1;
    },
    store_i32: (k, v) => { try { localStorage.setItem(K(k), String(v)); } catch {} },
    load_i32: (k, d) => {
      let v = null;
      try { v = localStorage.getItem(K(k)); } catch {}
      return v === null ? d : v | 0;
    },

    http_get: (p, m) => httpGet(str(p), m),
    http_get_ref: (h, m) => httpGet(strs[h], m),
    j_ok: (h) => (vals[h] != null && !(typeof vals[h] === "object" && "__error" in vals[h]) ? 1 : 0),
    j_err: (h, d) => { const v = vals[h]; strs[d] = v && v.__error ? v.__error : v == null ? "no response" : ""; },
    j_at: (h, p) => vNew(walk(h, p)),
    j_idx: (h, i) => vNew((vals[h] ?? [])[i]),
    j_has: (h, p) => (walk(h, p) != null ? 1 : 0),
    j_len: (h, p) => {
      const v = walk(h, p);
      return Array.isArray(v) || typeof v === "string" ? v.length : v && typeof v === "object" ? Object.keys(v).length : 0;
    },
    j_int: (h, p) => { const v = walk(h, p); return typeof v === "boolean" ? +v : Number(v) | 0; },
    j_str: (h, p, d) => { const v = walk(h, p); strs[d] = v == null ? "" : asText(v); return v == null ? 0 : 1; },
    j_key: (h, i, d) => { strs[d] = Object.keys(vals[h] ?? {})[i] ?? ""; },
    j_free: (h) => { if (h > 0) { vals[h] = undefined; vfree.push(h); } },
  };

  // Apps can declare their own @jscall imports and supply them here.
  if (opts.imports) Object.assign(js, opts.imports({ str, strs, vals, sNew, dispatch, text: txt }));

  for (const f of ["s_save", "s_load", "store_i32", "load_i32"]) {
    const base = js[f];
    js[f + "_at"] = (k, i, x) => base({ k: str(k) + "." + i }, x);
  }

  // Minimal WASI so print() works and _start-style exits don't crash.
  const wasi = {
    proc_exit: () => {},
    fd_write: (fd, iovs, n, out) => {
      const dv = new DataView(mem.buffer);
      let s = "", total = 0;
      for (let i = 0; i < n; i++) {
        const p = dv.getInt32(iovs + i * 8, true), l = dv.getInt32(iovs + i * 8 + 4, true);
        s += td.decode(new Uint8Array(mem.buffer, p, l)); total += l;
      }
      (fd === 2 ? console.error : console.log)(s.replace(/\n$/, ""));
      dv.setInt32(out, total, true);
      return 0;
    },
  };

  const imports = { js, wasi_snapshot_preview1: wasi };
  let instance;
  if (typeof url === "string") {
    const res = await fetch(url);
    // Streaming compile needs the application/wasm MIME type; fall back if absent.
    ({ instance } = (res.headers.get("content-type") || "").startsWith("application/wasm")
      ? await WebAssembly.instantiateStreaming(res, imports)
      : await WebAssembly.instantiate(await res.arrayBuffer(), imports));
  } else {
    ({ instance } = await WebAssembly.instantiate(url, imports));
  }
  ex = instance.exports;
  mem = ex.memory;

  // ------------------------------------------------------------ diff / patch
  const create = (v) => {
    if (v.t === "#") return (v.n = document.createTextNode(v.s));
    const n = (v.n = document.createElement(v.t));
    if (v.cls) n.className = v.cls;
    if (v.a) for (const k in v.a) n.setAttribute(k, v.a[k]);
    if (v.p) setProps(n, null, v.p);
    n.__ev = v.ev;
    for (const c of v.c) n.appendChild(create(c));
    return n;
  };

  const setProps = (n, o, p) => {
    for (const k in p) {
      if (k === "__focus") { if (!o || !o.__focus) queueMicrotask(() => n.focus()); continue; }
      if (n[k] !== p[k]) n[k] = p[k];
    }
  };

  const patch = (o, v) => {
    if (o.t !== v.t || o.k !== v.k) {
      const n = create(v);
      o.n.replaceWith(n);
      return;
    }
    const n = (v.n = o.n);
    if (v.t === "#") { if (o.s !== v.s) n.data = v.s; return; }
    if (o.cls !== v.cls) n.className = v.cls;
    if (o.a !== v.a) {
      const oa = o.a || {}, va = v.a || {};
      for (const k in oa) if (!(k in va)) n.removeAttribute(k);
      for (const k in va) if (oa[k] !== va[k]) n.setAttribute(k, va[k]);
    }
    if (v.p) setProps(n, o.p, v.p);
    n.__ev = v.ev;
    patchChildren(n, o.c, v.c);
  };

  const patchChildren = (parent, oc, vc) => {
    if (oc.length === 0 && vc.length === 0) return;
    const keyed = vc.length > 0 && vc[0].k !== null && oc.length > 0 && oc[0].k !== null;
    if (vc.length === 0 && parent.childNodes.length === oc.length) {
      parent.textContent = ""; // clearing a whole list: one DOM op
      return;
    }
    if (!keyed) {
      const m = Math.min(oc.length, vc.length);
      for (let i = 0; i < m; i++) patch(oc[i], vc[i]);
      for (let i = m; i < vc.length; i++) parent.appendChild(create(vc[i]));
      for (let i = m; i < oc.length; i++) oc[i].n.remove();
      return;
    }
    patchKeyed(parent, oc, vc);
  };

  // Keyed children: skip the common prefix and suffix, then match the middle by
  // key and move only the nodes outside the longest increasing subsequence of
  // old positions. Swapping two rows of 1,000 moves 2 nodes, not 998.
  const patchKeyed = (parent, oc, vc) => {
    let os = 0, oe = oc.length - 1, vs = 0, ve = vc.length - 1;
    while (os <= oe && vs <= ve && oc[os].k === vc[vs].k) patch(oc[os++], vc[vs++]);
    while (os <= oe && vs <= ve && oc[oe].k === vc[ve].k) patch(oc[oe--], vc[ve--]);
    const anchor = ve + 1 < vc.length ? vc[ve + 1].n : null;
    if (os > oe) {
      for (let i = vs; i <= ve; i++) parent.insertBefore(create(vc[i]), anchor);
      return;
    }
    if (vs > ve) {
      for (let i = os; i <= oe; i++) oc[i].n.remove();
      return;
    }
    const at = new Map();
    for (let i = vs; i <= ve; i++) at.set(vc[i].k, i);
    if (os === 0 && oe === oc.length - 1 && parent.childNodes.length === oc.length &&
        !oc.some((o) => at.has(o.k))) {
      // Nothing reused (e.g. replacing every row): drop all, build all.
      parent.textContent = "";
      for (const v of vc) parent.appendChild(create(v));
      return;
    }
    const src = new Int32Array(ve - vs + 1).fill(-1); // new slot -> old index
    let moved = false, last = -1;
    for (let i = os; i <= oe; i++) {
      const o = oc[i], j = at.get(o.k);
      if (j === undefined) { o.n.remove(); continue; }
      src[j - vs] = i;
      patch(o, vc[j]);
      if (j < last) moved = true; else last = j;
    }
    const keep = moved ? lis(src) : null;
    let li = keep ? keep.length - 1 : -1;
    let next = anchor;
    for (let j = ve; j >= vs; j--) {
      const v = vc[j], p = j - vs;
      if (src[p] === -1) parent.insertBefore(create(v), next);
      else if (moved) {
        if (li >= 0 && keep[li] === p) li--;
        else parent.insertBefore(v.n, next);
      }
      next = v.n;
    }
  };

  // Positions (into a) of a longest strictly increasing subsequence, skipping -1.
  const lis = (a) => {
    const prev = new Int32Array(a.length), tails = [];
    for (let i = 0; i < a.length; i++) {
      const x = a[i];
      if (x === -1) continue;
      let lo = 0, hi = tails.length;
      while (lo < hi) { const m = (lo + hi) >> 1; if (a[tails[m]] < x) lo = m + 1; else hi = m; }
      prev[i] = lo > 0 ? tails[lo - 1] : -1;
      tails[lo] = i;
    }
    const out = new Array(tails.length);
    for (let k = tails.length - 1, i = tails[k]; k >= 0; k--, i = prev[i]) out[k] = i;
    return out;
  };

  // ------------------------------------------------------------ render
  let prev = null;
  // opts.onRender(stats) runs after each patch with timings in ms:
  //   { start, update, view, patch, end, nodes }
  // where start is the first dispatch since the previous render.
  function render() {
    queued = false;
    const t0 = performance.now();
    if (frameQ.length) {
      const q = frameQ; frameQ = [];
      for (let i = 0; i < q.length; i += 2) ex.update(q[i], q[i + 1]);
    }
    const t1 = performance.now();
    const top = node("#root");
    stack = []; cur = top; nodes = 0;
    ex.view();
    const t2 = performance.now();
    if (prev === null) {
      root.textContent = "";
      for (const c of top.c) root.appendChild(create(c));
    } else {
      patchChildren(root, prev.c, top.c);
    }
    prev = top;
    const t3 = performance.now();
    const stats = { start: since || t0, update: tUpdate + (t1 - t0),
                    view: t2 - t1, patch: t3 - t2, end: t3, nodes };
    since = 0; tUpdate = 0;
    if (opts.onRender) opts.onRender(stats);
  }

  // ------------------------------------------------------------ events
  const find = (t, kind) => {
    for (let n = t; n && n !== root; n = n.parentNode) if (n.__ev && n.__ev[kind]) return n.__ev[kind];
    return null;
  };
  const on = (type, kind, pre) =>
    root.addEventListener(type, (e) => {
      if (pre && !pre(e)) return;
      const h = find(e.target, kind);
      if (!h) return;
      if (kind === "input") strs[EVENT] = e.target.value;
      dispatch(h[0], h[1]);
    });
  on("click", "click");
  on("dblclick", "dblclick");
  on("input", "input");
  on("keydown", "enter", (e) => e.key === "Enter" && !e.isComposing);

  // Run module-level code (which calls init()), then first render.
  ex.__main__global_stmts();
  render();
  return { dispatch, render, exports: ex, strs, vals };
}
