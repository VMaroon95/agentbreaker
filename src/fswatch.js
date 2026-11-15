import { readdirSync, lstatSync } from "node:fs";
import { join, sep } from "node:path";

// Polling snapshot diff. Slower than inotify, but identical on every OS and cannot miss a burst of events.
// Limits: symlinked directories are not followed; files created and removed between two polls are never seen;
// the walk is synchronous, so a huge tree stalls the event loop for the duration of each poll.
// If the tree has more than maxEntries files the snapshot is partial: map.truncated is set.
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
      if (map.size >= maxEntries) { map.truncated = true; return map; }
      if (st.isDirectory()) stack.push(r);
      // ctime cannot be set from userland, so `touch -r` / utimes() cannot hide an in-place rewrite
      else map.set(r, `${st.size}:${st.mtimeMs}:${st.ctimeMs}:${st.ino}`);
    }
  }
  return map;
}

export function diff(prev, next) {
  const writes = [], deletes = [];
  for (const [k, v] of next) if (prev.get(k) !== v) writes.push(k);
  // A truncated snapshot lists an arbitrary subset, so absence proves nothing: never report deletes from it.
  if (!prev.truncated && !next.truncated) for (const k of prev.keys()) if (!next.has(k)) deletes.push(k);
  return { writes, deletes };
}

export class FsMonitor {
  constructor({ root, breaker, audit, intervalMs = 500, maxEntries = 200_000 }) {
    this.root = root; this.breaker = breaker; this.audit = audit; this.intervalMs = intervalMs; this.maxEntries = maxEntries;
    this.warned = false;
    this.prev = this.#snap();
    this.timer = null;
  }
  #snap() {
    const s = snapshot(this.root, (r) => this.breaker.isIgnored(r.split(sep).join("/")), this.maxEntries);
    if (s.truncated && !this.warned) { this.warned = true; this.audit("fs_truncated", { max_entries: this.maxEntries }); }
    return s;
  }
  poll() {
    const next = this.#snap();
    const { writes, deletes } = diff(this.prev, next);
    this.prev = next;
    for (const p of deletes) { this.audit("fs_delete", { path: p }); this.breaker.addFsEvent("delete", p); }
    for (const p of writes) { this.audit("fs_write", { path: p }); this.breaker.addFsEvent("write", p); }
  }
  start() { this.timer = setInterval(() => this.poll(), this.intervalMs); this.timer.unref?.(); }
  stop() { clearInterval(this.timer); }
}
