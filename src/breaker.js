import { EventEmitter } from "node:events";
import { globToRegExp } from "./policy.js";

const MIN = 60_000, HOUR = 3_600_000;

// Pure accounting + limit checks. No I/O, injectable clock, so it can be tested exhaustively.
export class Breaker extends EventEmitter {
  constructor(policy, now = Date.now) {
    super();
    this.policy = policy;
    this.now = now;
    this.limits = { ...policy.limits };   // mutable copy: resume() can raise cumulative limits
    this.started = now();
    this.usd = 0; this.tokens = 0; this.uploadBytes = 0; this.blocked = 0;
    this.unpriced = new Set();
    this.win = { requests: [], deletes: [], writes: [], spend: [] };
    this.protectedRe = policy.protected_paths.map((g) => [g, globToRegExp(g)]);
    this.ignoreRe = policy.ignore.map((g) => globToRegExp(g.replace(/\/+$/, "") + "/**"));
    this.ignoreExact = policy.ignore.map((g) => globToRegExp(g.replace(/\/+$/, "")));
    this.state = "ok";
    this.lastTrip = null;
  }

  price(model) {
    const m = String(model ?? "");
    return this.policy.prices.find((p) => m.startsWith(p.match)) ?? null;
  }

  isIgnored(rel) {
    return this.ignoreRe.some((r) => r.test(rel)) || this.ignoreExact.some((r) => r.test(rel));
  }

  trip(reason, limit, value) {
    if (this.state === "tripped") return this.lastTrip;
    this.state = "tripped";
    this.lastTrip = { reason, limit, value, at: new Date(this.now()).toISOString() };
    this.emit("trip", this.lastTrip);
    return this.lastTrip;
  }

  #slide(arr, span) {
    const cut = this.now() - span;
    while (arr.length && arr[0].t < cut) arr.shift();
  }
  #sum(arr) { return arr.reduce((a, e) => a + e.n, 0); }

  addRequest() {
    const t = this.now();
    this.win.requests.push({ t, n: 1 });
    this.#slide(this.win.requests, MIN);
    const lim = this.limits.max_requests_per_minute;
    if (lim && this.#sum(this.win.requests) > lim) this.trip("too many API requests per minute (possible loop)", lim, this.#sum(this.win.requests));
  }

  addUsage({ model, input = 0, output = 0 }) {
    input = Math.max(0, Number(input) || 0); output = Math.max(0, Number(output) || 0);
    this.tokens += input + output;
    const price = this.price(model);
    let cost = 0;
    if (price) cost = (input * price.input_per_mtok + output * price.output_per_mtok) / 1e6;
    else if (this.limits.max_usd || this.limits.max_usd_per_hour) this.unpriced.add(String(model ?? "unknown"));
    this.usd += cost;
    if (cost) { this.win.spend.push({ t: this.now(), n: cost }); this.#slide(this.win.spend, HOUR); }
    const L = this.limits;
    if (L.max_usd && this.usd > L.max_usd) this.trip("spend limit reached", L.max_usd, round(this.usd));
    else if (L.max_usd_per_hour && this.#sum(this.win.spend) > L.max_usd_per_hour) this.trip("hourly spend limit reached", L.max_usd_per_hour, round(this.#sum(this.win.spend)));
    else if (L.max_tokens && this.tokens > L.max_tokens) this.trip("token limit reached", L.max_tokens, this.tokens);
    return cost;
  }

  // kind: "write" | "delete". rel: path relative to the workspace, with forward slashes.
  addFsEvent(kind, rel) {
    if (this.isIgnored(rel)) return;
    const hit = this.protectedRe.find(([, re]) => re.test(rel));
    if (hit) this.trip(`protected path ${kind === "delete" ? "deleted" : "modified"}: ${rel}`, hit[0], rel);
    const key = kind === "delete" ? "deletes" : "writes";
    this.win[key].push({ t: this.now(), n: 1 });
    this.#slide(this.win[key], MIN);
    const lim = this.limits[`max_${key}_per_minute`];
    if (lim && this.#sum(this.win[key]) > lim) this.trip(`too many file ${key} per minute`, lim, this.#sum(this.win[key]));
  }

  addUpload(host, bytes) {
    this.uploadBytes += bytes;
    const lim = this.limits.max_upload_mb;
    if (lim && this.uploadBytes > lim * 1024 * 1024) this.trip("upload volume limit reached", `${lim} MB`, `${(this.uploadBytes / 1048576).toFixed(1)} MB (last host: ${host})`);
  }

  addBlocked(host) {
    this.blocked++;
    const lim = this.limits.max_blocked_attempts;
    if (lim && this.blocked >= lim) this.trip("repeated blocked network attempts", lim, `${this.blocked} (last: ${host})`);
  }

  tick() {
    const lim = this.limits.max_runtime_minutes;
    if (lim && this.now() - this.started > lim * MIN) this.trip("runtime limit reached", lim, "minutes");
  }

  // After a human approves continuing: clear windows, and give cumulative limits one more increment.
  resume() {
    if (this.state !== "tripped") return;
    const L = this.limits, base = this.policy.limits;
    if (L.max_usd && this.usd > L.max_usd) L.max_usd = this.usd + base.max_usd;
    if (L.max_tokens && this.tokens > L.max_tokens) L.max_tokens = this.tokens + base.max_tokens;
    if (L.max_upload_mb && this.uploadBytes > L.max_upload_mb * 1048576) L.max_upload_mb = this.uploadBytes / 1048576 + base.max_upload_mb;
    if (L.max_runtime_minutes && this.now() - this.started > L.max_runtime_minutes * MIN) L.max_runtime_minutes += base.max_runtime_minutes;
    for (const k of Object.keys(this.win)) this.win[k] = [];
    this.blocked = 0;
    this.state = "ok";
    this.lastTrip = null;
  }

  stats() {
    return { usd: round(this.usd), tokens: this.tokens, upload_mb: +(this.uploadBytes / 1048576).toFixed(2), blocked: this.blocked, unpriced_models: [...this.unpriced] };
  }
}
const round = (n) => Math.round(n * 10000) / 10000;
