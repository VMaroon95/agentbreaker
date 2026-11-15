import { openSync, writeSync, closeSync, mkdirSync, readFileSync, existsSync, constants } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";

const GENESIS = "0".repeat(64);
const sha = (line) => createHash("sha256").update(line).digest("hex");

// Hash of the last non-empty line of an existing log (so a second run continues the chain instead of breaking it).
function tailHash(file) {
  if (!existsSync(file)) return GENESIS;
  const lines = readFileSync(file, "utf8").split("\n");
  for (let i = lines.length - 1; i >= 0; i--) if (lines[i]) return sha(lines[i]);
  return GENESIS;
}

// Append-only JSONL with a hash chain. This detects accidental damage and naive edits. It is NOT
// tamper-proof against someone who can rewrite the file: the chain is unkeyed, so they can recompute it.
// Keep the head hash printed at exit (see `verify-log --head`) somewhere the agent cannot write.
export class AuditLog {
  constructor(file) {
    mkdirSync(dirname(file), { recursive: true });
    this.prev = tailHash(file);
    // O_NOFOLLOW: refuse to append through a symlink planted at the log path.
    this.fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
    this.lines = 0;
  }
  write(event, data = {}) {
    const rec = { t: new Date().toISOString(), event, ...data };
    rec.event = event; rec.prev = this.prev;   // caller data can never overwrite the chain fields
    const line = JSON.stringify(rec);
    const buf = Buffer.from(line + "\n");
    let off = 0;
    while (off < buf.length) off += writeSync(this.fd, buf, off);
    this.prev = sha(line);
    this.lines++;
  }
  get head() { return this.prev; }
  close() { try { closeSync(this.fd); } catch { /* already closed */ } }
}

// expectHead: optional hash of the final line recorded elsewhere; detects truncation and wholesale rewrites.
export function verifyChain(text, { expectHead } = {}) {
  let prev = GENESIS, n = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    let rec; try { rec = JSON.parse(line); } catch { return { ok: false, line: n + 1 }; }
    if (!rec || typeof rec !== "object" || Array.isArray(rec) || rec.prev !== prev) return { ok: false, line: n + 1 };
    prev = sha(line); n++;
  }
  if (expectHead !== undefined && expectHead !== prev) return { ok: false, line: n + 1, reason: "head mismatch (log truncated, extended or rewritten)" };
  return { ok: true, lines: n };
}

// Hash of the last non-empty line (the value to store out-of-band and later pass as --head).
export function chainHead(text) {
  const lines = text.split("\n").filter(Boolean);
  return lines.length ? sha(lines[lines.length - 1]) : GENESIS;
}
