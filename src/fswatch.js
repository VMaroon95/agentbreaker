import { readdirSync, lstatSync } from "node:fs";
import { join, sep } from "node:path";

// Polling snapshot diff. Slower than inotify, but identical on every OS and cannot miss a burst of events.
export function snapshot(root, isIgnored, maxEntries = 200_000) {
  const map = new Map();
  const stack = [""];
  while (stack.length) {
    const rel = stack.pop();
    let names;
    try { names = readdirSync(join(root, rel)); } catch { continue; }
    for (const n of names) {
      const r = rel ? `${rel}/${n}` : n;
      if (isIgnored(r)) continue;
      let st;
      try { st = lstatSync(join(root, r)); } catch { continue; }
      if (map.size >= maxEntries) return map;
      if (st.isDirectory()) stack.push(r);
      else map.set(r, `${st.size}:${st.mtimeMs}:${st.ino}`);
    }
  }
  return map;
}

export function diff(prev, next) {
  const writes = [], deletes = [];
  for (const [k, v] of next) if (prev.get(k) !== v) writes.push(k);
  for (const k of prev.keys()) if (!next.has(k)) deletes.push(k);
  return { writes, deletes };
}

export class FsMonitor {
  constructor({ root, breaker, audit, intervalMs = 500 }) {
    this.root = root; this.breaker = breaker; this.audit = audit; this.intervalMs = intervalMs;
    this.prev = snapshot(root, (r) => breaker.isIgnored(r.split(sep).join("/")));
    this.timer = null;
  }
  poll() {
    const next = snapshot(this.root, (r) => this.breaker.isIgnored(r));
    const { writes, deletes } = diff(this.prev, next);
    this.prev = next;
    for (const p of deletes) { this.audit("fs_delete", { path: p }); this.breaker.addFsEvent("delete", p); }
    for (const p of writes) { this.audit("fs_write", { path: p }); this.breaker.addFsEvent("write", p); }
  }
  start() { this.timer = setInterval(() => this.poll(), this.intervalMs); this.timer.unref?.(); }
  stop() { clearInterval(this.timer); }
}
