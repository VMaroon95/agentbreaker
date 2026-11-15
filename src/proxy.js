import http from "node:http";
import https from "node:https";
import net from "node:net";
import zlib from "node:zlib";
import { StringDecoder } from "node:string_decoder";
import { hostMatches, normalizeHost } from "./policy.js";

// Hosts reachable through the CONNECT tunnel without being listed: only the configured model upstreams.
export function modelHosts(policy) {
  return Object.values(policy.upstreams).map((u) => new URL(u).hostname);
}

const num = (v) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : 0);
const JSON_CAP = 4 * 1024 * 1024;     // a JSON body is kept whole up to this size
const SSE_CAP = 64 * 1024;            // an SSE stream is parsed incrementally; only this much unparsed text is buffered

// Pulls token usage out of a JSON body or an SSE stream (Anthropic and OpenAI shapes, incl. the Responses API).
// Memory is bounded for any body size and any content: SSE is parsed event by event as it arrives.
export class UsageParser {
  constructor(contentType = "") {
    this.buf = ""; this.head = ""; this.truncated = false;
    this.model = null; this.input = 0; this.output = 0;
    this.ct = contentType; this.sse = /text\/event-stream/i.test(contentType);
    this.rem = ""; this.data = [];
    this.dec = new StringDecoder("utf8");
  }
  push(chunk) {
    this.buf += typeof chunk === "string" ? chunk : this.dec.write(chunk);
    if (this.sse) { if (this.buf.length > SSE_CAP) this.#feed(); }
    else if (this.buf.length > JSON_CAP) {
      if (!this.head) this.head = this.buf.slice(0, 64 * 1024);
      this.buf = this.buf.slice(-1024 * 1024); this.truncated = true;
    }
  }
  finish(contentType = "") {
    if (contentType && !this.ct) { this.ct = contentType; this.sse = /text\/event-stream/i.test(contentType); }
    if (this.sse) { this.#feed(true); }
    else {
      let ok = false;
      if (!this.truncated) try { this.#absorb(JSON.parse(this.buf)); ok = true; } catch { /* not JSON */ }
      if (!ok && this.truncated) this.#scan();
    }
    return { model: this.model, input: this.input, output: this.output };
  }
  // Oversized JSON body: JSON.parse is impossible, so regex out the usage counters (they sit at the end) and the model (at the start).
  #scan() {
    const m = /"model"\s*:\s*"([^"\\]{1,200})"/.exec(this.head + this.buf.slice(0, 4096));
    if (m) this.model = m[1];
    const grab = (k) => { let best = 0; for (const x of this.buf.matchAll(new RegExp(`"${k}"\\s*:\\s*(\\d{1,15})\\b`, "g"))) best = Math.max(best, Number(x[1])); return best; };
    this.input = Math.max(this.input, grab("input_tokens") + grab("cache_creation_input_tokens") + grab("cache_read_input_tokens"), grab("prompt_tokens"));
    this.output = Math.max(this.output, grab("output_tokens"), grab("completion_tokens"));
  }
  // SSE per the spec: lines end with CRLF, LF or CR; an event is its `data:` lines joined with "\n", ended by a blank line.
  #feed(final = false) {
    let text = this.rem + this.buf; this.buf = ""; this.rem = "";
    let cr = "";
    if (!final && text.endsWith("\r")) { cr = "\r"; text = text.slice(0, -1); }
    const lines = text.split(/\r\n|\r|\n/);
    const last = final ? null : lines.pop();
    for (const line of lines) this.#line(line);
    if (final) this.#line("");   // flush an event that was not terminated by a blank line
    else this.rem = last + cr;
  }
  #line(line) {
    if (line === "") {
      if (!this.data.length) return;
      const lines = this.data; this.data = [];
      const joined = lines.join("\n");
      if (joined.trim() === "[DONE]") return;
      try { this.#absorb(JSON.parse(joined)); return; } catch { /* maybe a server that omits blank lines */ }
      if (lines.length > 1) for (const l of lines) { try { this.#absorb(JSON.parse(l)); } catch { /* partial */ } }
      return;
    }
    if (line.startsWith(":")) return;
    const i = line.indexOf(":");
    const field = i < 0 ? line : line.slice(0, i);
    if (field !== "data") return;
    let v = i < 0 ? "" : line.slice(i + 1);
    if (v.startsWith(" ")) v = v.slice(1);
    this.data.push(v);
  }
  #absorb(o) {
    if (!o || typeof o !== "object") return;
    for (const w of [o, o.message, o.response]) {
      if (!w || typeof w !== "object") continue;
      if (typeof w.model === "string") this.model = w.model;
      const u = w.usage;
      if (u && typeof u === "object") {
        // Anthropic streams: message_start has input_tokens, message_delta has cumulative output_tokens -> take max.
        const inp = num(u.input_tokens ?? u.prompt_tokens) + num(u.cache_creation_input_tokens) + num(u.cache_read_input_tokens);
        const out = num(u.output_tokens ?? u.completion_tokens);
        this.input = Math.max(this.input, inp);
        this.output = Math.max(this.output, out);
      }
    }
  }
}

// Headers that describe one hop and must not be forwarded (RFC 9110 7.6.1), plus anything named in `Connection`.
const HOP = ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade", "expect"];
function stripHop(h) {
  const out = { ...h };
  for (const t of String(h.connection ?? "").split(",")) { const k = t.trim().toLowerCase(); if (k) delete out[k]; }
  for (const k of HOP) delete out[k];
  return out;
}

export function createProxy({ policy, breaker, audit, upstreamIdleMs = 15 * 60_000, connectTimeoutMs = 30_000 }) {
  const always = modelHosts(policy);
  const allowed = (host) => hostMatches(host, always) || hostMatches(host, policy.egress.allow);
  const enforce = policy.egress.mode === "enforce";
  const frozen = () => breaker.state === "tripped";
  breaker.setMaxListeners?.(0);   // one trip listener per open CONNECT tunnel

  function deny(host, why) {
    audit("egress_blocked", { host, why });
    breaker.addBlocked(host);
  }

  const server = http.createServer((req, res) => {
    try {
      if (frozen()) { res.writeHead(503, { "content-type": "application/json" }); return res.end(JSON.stringify({ error: "agentbreaker: tripped, requests paused", reason: breaker.lastTrip?.reason })); }
      if (req.url.startsWith("/")) return reverse(req, res);
      return forward(req, res);
    } catch (e) {
      audit("proxy_error", { message: String(e?.message ?? e) });
      if (!res.headersSent) { try { res.writeHead(500); } catch { /* closed */ } res.end("agentbreaker: internal error"); } else res.destroy();
    }
  });

  // Reverse mode: ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/anthropic  -> counts tokens.
  function reverse(req, res) {
    const m = /^\/([a-z0-9_-]+)(\/.*)?$/i.exec(req.url);
    const base = m && Object.hasOwn(policy.upstreams, m[1]) ? policy.upstreams[m[1]] : null;
    if (!base) { res.writeHead(404); return res.end("agentbreaker: unknown upstream"); }
    // Never let the client pick the host: "//evil.com/x" and "/\evil.com" would otherwise resolve to another origin
    // and carry the agent's API key with them.
    const rest = m[2] ?? "/";
    const b = new URL(base);
    const prefix = b.pathname.replace(/\/+$/, "");
    let target;
    try { target = new URL(prefix + rest, b.origin); } catch { target = null; }
    if (!target || /^\/[\\/]/.test(rest) || rest.split("?")[0].includes("\\") || target.origin !== b.origin) { res.writeHead(400); return res.end("agentbreaker: bad path"); }
    breaker.addRequest();
    const headers = stripHop(req.headers);
    headers.host = target.host;
    headers["accept-encoding"] = "identity";   // compressed bodies would hide token usage from the parser
    const out = (target.protocol === "http:" ? http : https).request(target, { method: req.method, headers }, (up) => {
      const ct = String(up.headers["content-type"] ?? "");
      const enc = String(up.headers["content-encoding"] ?? "").toLowerCase().trim();
      const parser = new UsageParser(ct);
      let dec = null;
      if (enc === "gzip" || enc === "x-gzip") dec = zlib.createGunzip();
      else if (enc === "deflate") dec = zlib.createInflate();
      else if (enc === "br") dec = zlib.createBrotliDecompress();
      let finalized = false;
      const finalize = () => {
        if (finalized) return; finalized = true;
        const u = parser.finish(ct);
        if (u.input || u.output) {
          const cost = breaker.addUsage(u);
          audit("usage", { upstream: m[1], model: u.model, input: u.input, output: u.output, usd: cost, ...(breaker.price(u.model) ? {} : { unpriced: true }) });
        } else if (req.method === "POST" && up.statusCode >= 200 && up.statusCode < 300) {
          audit("usage_unparsed", { upstream: m[1], status: up.statusCode, content_type: ct, content_encoding: enc || undefined });
        }
      };
      if (dec) { dec.on("data", (c) => parser.push(c)); dec.on("error", () => {}); dec.on("close", finalize); }
      const hdrs = stripHop(up.headers);
      res.writeHead(up.statusCode, up.statusMessage, hdrs);
      up.on("data", (c) => {
        if (dec) dec.write(c); else parser.push(c);
        if (!res.destroyed && !res.write(c)) { up.pause(); const go = () => up.resume(); res.once("drain", go); res.once("close", go); }
      });
      let decEnded = false;
      const endDec = () => { if (dec && !decEnded) { decEnded = true; dec.end(); } };
      up.on("end", () => { endDec(); res.end(); });
      up.on("close", () => { if (dec) endDec(); else finalize(); if (!res.writableEnded) res.destroy(); });
      up.on("error", () => res.destroy());
    });
    out.setTimeout(upstreamIdleMs, () => out.destroy(Object.assign(new Error("upstream idle timeout"), { code: "ETIMEDOUT" })));
    out.on("error", (e) => {
      if (res.headersSent) return res.destroy();
      res.writeHead(e.code === "ETIMEDOUT" ? 504 : 502); res.end(`agentbreaker: upstream error ${e.code ?? ""}`);
    });
    req.on("data", (c) => breaker.addUpload(target.hostname, c.length));
    req.on("aborted", () => out.destroy());   // half-sent request: do not leave the upstream socket waiting forever
    req.pipe(out);
  }

  // Plain-HTTP forward proxy.
  function forward(req, res) {
    let u;
    try { u = new URL(req.url); } catch { res.writeHead(400); return res.end("bad url"); }
    if (u.protocol !== "http:") { res.writeHead(400); return res.end("agentbreaker: only http:// absolute URLs can be forwarded (use CONNECT for https)"); }
    if (enforce && !allowed(u.hostname)) { deny(u.hostname, "not in allowlist"); res.writeHead(403); return res.end("agentbreaker: egress blocked"); }
    audit("egress", { host: u.hostname, method: req.method });
    const headers = stripHop(req.headers);
    headers.host = u.host;   // the Host header must match the host we vetted, or an allowed IP can front for another site
    const out = http.request(u, { method: req.method, headers }, (up) => {
      res.writeHead(up.statusCode, up.statusMessage, stripHop(up.headers));
      up.pipe(res);
      up.on("error", () => res.destroy());
    });
    out.setTimeout(upstreamIdleMs, () => out.destroy(Object.assign(new Error("idle"), { code: "ETIMEDOUT" })));
    out.on("error", (e) => { if (res.headersSent) return res.destroy(); res.writeHead(e.code === "ETIMEDOUT" ? 504 : 502); res.end(); });
    req.on("data", (c) => breaker.addUpload(u.hostname, c.length));
    req.on("aborted", () => out.destroy());
    req.pipe(out);
  }

  // HTTPS tunnel. We can only see host and byte counts, not contents.
  server.on("connect", (req, sock, head) => {
    const m = /^(\[[^\]]+\]|[^:\[\]]+):(\d{1,5})$/.exec(req.url);
    const port = m ? Number(m[2]) : 0;
    const host = m ? normalizeHost(m[1]) : "";
    if (!m || !host || port < 1 || port > 65535) { sock.end("HTTP/1.1 400 Bad Request\r\n\r\n"); return; }
    if (frozen()) { sock.end("HTTP/1.1 503 Paused\r\n\r\n"); return; }
    if (enforce && !allowed(host)) { deny(host, "not in allowlist"); sock.end("HTTP/1.1 403 Blocked by agentbreaker\r\n\r\n"); return; }
    audit("egress", { host, port, method: "CONNECT" });
    let established = false, closed = false;
    const end = () => {
      if (closed) return; closed = true;
      clearTimeout(timer); breaker.off("trip", end);
      if (!established && sock.writable) sock.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      up.destroy(); sock.destroy();
    };
    const up = net.connect(port, host, () => {
      clearTimeout(timer);
      established = true;
      sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) { breaker.addUpload(host, head.length); up.write(head); }
      sock.on("data", (c) => breaker.addUpload(host, c.length));   // attached only now: earlier bytes must not be consumed unforwarded
      up.pipe(sock); sock.pipe(up);
    });
    const timer = setTimeout(end, connectTimeoutMs);
    up.on("error", end); sock.on("error", end); up.on("close", end); sock.on("close", end);
    // A tunnel opened before a trip must not outlive it.
    breaker.on("trip", end);
  });

  server.on("clientError", (_e, sock) => { try { if (sock.writable) sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); } catch { /* gone */ } sock.destroy(); });
  return server;
}
