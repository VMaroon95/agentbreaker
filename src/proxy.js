import http from "node:http";
import https from "node:https";
import net from "node:net";
import { hostMatches } from "./policy.js";

// Hosts reachable through the CONNECT tunnel without being listed: only the configured model upstreams.
export function modelHosts(policy) {
  return Object.values(policy.upstreams).map((u) => new URL(u).hostname);
}

// Pulls token usage out of a JSON body or an SSE stream (Anthropic and OpenAI shapes).
export class UsageParser {
  constructor() { this.buf = ""; this.model = null; this.input = 0; this.output = 0; this.json = false; }
  push(chunk) {
    this.buf += chunk;
    if (this.buf.length > 4 * 1024 * 1024) this.buf = this.buf.slice(-1024 * 1024); // never grow unbounded
  }
  finish(contentType = "") {
    const text = this.buf;
    if (/text\/event-stream/.test(contentType)) {
      for (const line of text.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const d = line.slice(5).trim();
        if (!d || d === "[DONE]") continue;
        try { this.#absorb(JSON.parse(d)); } catch { /* partial line */ }
      }
    } else {
      try { this.#absorb(JSON.parse(text)); } catch { /* not JSON */ }
    }
    return { model: this.model, input: this.input, output: this.output };
  }
  #absorb(o) {
    if (!o || typeof o !== "object") return;
    const msg = o.message && typeof o.message === "object" ? o.message : o;
    if (typeof msg.model === "string") this.model = msg.model;
    if (typeof o.model === "string") this.model = o.model;
    const u = msg.usage ?? o.usage;
    if (u && typeof u === "object") {
      // Anthropic streams: message_start has input_tokens, message_delta has cumulative output_tokens -> take max.
      const inp = (u.input_tokens ?? u.prompt_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0);
      const out = u.output_tokens ?? u.completion_tokens ?? 0;
      if (Number.isFinite(inp)) this.input = Math.max(this.input, inp);
      if (Number.isFinite(out)) this.output = Math.max(this.output, out);
    }
  }
}

export function createProxy({ policy, breaker, audit }) {
  const always = modelHosts(policy);
  const allowed = (host) => hostMatches(host, always) || hostMatches(host, policy.egress.allow);
  const enforce = policy.egress.mode === "enforce";
  const frozen = () => breaker.state === "tripped";

  function deny(host, why) {
    audit("egress_blocked", { host, why });
    breaker.addBlocked(host);
  }

  const server = http.createServer((req, res) => {
    if (frozen()) { res.writeHead(503, { "content-type": "application/json" }); return res.end(JSON.stringify({ error: "agentbreaker: tripped, requests paused", reason: breaker.lastTrip?.reason })); }
    if (req.url.startsWith("/")) return reverse(req, res);
    return forward(req, res);
  });

  // Reverse mode: ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/anthropic  -> counts tokens.
  function reverse(req, res) {
    const m = /^\/([a-z0-9_-]+)(\/.*)?$/i.exec(req.url);
    const base = m && Object.hasOwn(policy.upstreams, m[1]) ? policy.upstreams[m[1]] : null;
    if (!base) { res.writeHead(404); return res.end("agentbreaker: unknown upstream"); }
    const target = new URL((m[2] ?? "/"), base);
    breaker.addRequest();
    const headers = { ...req.headers, host: target.host };
    delete headers["proxy-connection"];
    const out = (target.protocol === "http:" ? http : https).request(target, { method: req.method, headers }, (up) => {
      const parser = new UsageParser();
      res.writeHead(up.statusCode, up.headers);
      up.on("data", (c) => { parser.push(c.toString("utf8")); res.write(c); });
      up.on("end", () => {
        res.end();
        const u = parser.finish(String(up.headers["content-type"] ?? ""));
        if (u.input || u.output) {
          const cost = breaker.addUsage(u);
          audit("usage", { upstream: m[1], model: u.model, input: u.input, output: u.output, usd: cost });
        }
      });
      up.on("error", () => res.destroy());
    });
    out.on("error", (e) => { if (!res.headersSent) res.writeHead(502); res.end(`agentbreaker: upstream error ${e.code ?? ""}`); });
    req.on("data", (c) => breaker.addUpload(target.hostname, c.length));
    req.pipe(out);
  }

  // Plain-HTTP forward proxy.
  function forward(req, res) {
    let u;
    try { u = new URL(req.url); } catch { res.writeHead(400); return res.end("bad url"); }
    if (enforce && !allowed(u.hostname)) { deny(u.hostname, "not in allowlist"); res.writeHead(403); return res.end("agentbreaker: egress blocked"); }
    audit("egress", { host: u.hostname, method: req.method });
    const out = http.request(u, { method: req.method, headers: req.headers }, (up) => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
    out.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.on("data", (c) => breaker.addUpload(u.hostname, c.length));
    req.pipe(out);
  }

  // HTTPS tunnel. We can only see host and byte counts, not contents.
  server.on("connect", (req, sock, head) => {
    const m = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(req.url);
    if (!m) { sock.end("HTTP/1.1 400 Bad Request\r\n\r\n"); return; }
    const host = m[1].replace(/^\[|\]$/g, ""), port = Number(m[2]);
    if (frozen()) { sock.end("HTTP/1.1 503 Paused\r\n\r\n"); return; }
    if (enforce && !allowed(host)) { deny(host, "not in allowlist"); sock.end("HTTP/1.1 403 Blocked by agentbreaker\r\n\r\n"); return; }
    audit("egress", { host, port, method: "CONNECT" });
    const up = net.connect(port, host, () => {
      sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
    });
    sock.on("data", (c) => breaker.addUpload(host, c.length));
    const end = () => { up.destroy(); sock.destroy(); };
    up.on("error", end); sock.on("error", end); up.on("close", end); sock.on("close", end);
    // A tunnel opened before a trip must not outlive it.
    breaker.on("trip", end);
  });

  server.on("clientError", (_e, sock) => sock.destroy());
  return server;
}
