import { openSync, writeSync, closeSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

// Append-only JSONL with a hash chain, so tampering with earlier lines is detectable.
export class AuditLog {
  constructor(file) {
    mkdirSync(dirname(file), { recursive: true });
    this.fd = openSync(file, "a", 0o600);
    this.prev = "0".repeat(64);
  }
  write(event, data = {}) {
    const rec = { t: new Date().toISOString(), event, ...data, prev: this.prev };
    const line = JSON.stringify(rec);
    this.prev = createHash("sha256").update(line).digest("hex");
    writeSync(this.fd, line + "\n");
  }
  close() { try { closeSync(this.fd); } catch { /* already closed */ } }
}

export function verifyChain(text) {
  let prev = "0".repeat(64), n = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    let rec; try { rec = JSON.parse(line); } catch { return { ok: false, line: n + 1 }; }
    if (rec.prev !== prev) return { ok: false, line: n + 1 };
    prev = createHash("sha256").update(line).digest("hex"); n++;
  }
  return { ok: true, lines: n };
}
