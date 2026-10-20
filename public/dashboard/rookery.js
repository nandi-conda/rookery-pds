// Dashboard-specific imports for app.wasm (declared with @jscall in dashboard/app.py).
const B32 = "234567abcdefghijklmnopqrstuvwxyz";

export function rookeryImports({ strs, text: txt }) {
  const imports = {
    pds_base: (d) => {
      const q = new URLSearchParams(location.search).get("pds");
      strs[d] = (q && /^https?:\/\//.test(q) ? q : document.documentElement.dataset.pds || location.origin).replace(/\/$/, "");
    },
    // A TID is 13 base32-sortable chars; the top 53 bits are microseconds.
    tid_secs: (h) => {
      const s = strs[h] || "";
      if (!/^[2-7a-z]{13}$/.test(s)) return 0;
      let n = 0n;
      for (const c of s) n = n * 32n + BigInt(B32.indexOf(c));
      return Number((n >> 10n) / 1000000n);
    },
    ago: (secs) => txt(rel(secs * 1000)),
    date_text: (h) => { const t = Date.parse(strs[h]); txt(isNaN(t) ? strs[h] || "" : rel(t)); },
  };
  return imports;
}

function rel(ms) {
  const d = Math.max(0, (Date.now() - ms) / 1000);
  if (d < 60) return "just now";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  if (d < 86400 * 60) return Math.floor(d / 86400) + "d ago";
  return new Date(ms).toISOString().slice(0, 10);
}
