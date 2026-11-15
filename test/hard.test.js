// Adversarial regression tests. Each block documents a bug that was found by attacking the tool.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import zlib from "node:zlib";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync, symlinkSync, utimesSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Breaker } from "../src/breaker.js";
import { normalizePolicy, globToRegExp, hostMatches, loadPolicy } from "../src/policy.js";
import { UsageParser, createProxy } from "../src/proxy.js";
import { snapshot, diff, FsMonitor } from "../src/fswatch.js";
import { AuditLog, verifyChain, chainHead } from "../src/audit.js";
import { run } from "../src/run.js";

const P = (o) => normalizePolicy(o);
const NODE = process.execPath;
const CLI = resolve(import.meta.dirname, "../bin/agentbreaker.js");
const tmp = (p = "abh-") => mkdtempSync(join(tmpdir(), p));
const clock = (t0 = 1_000_000) => { let t = t0; const f = () => t; f.adv = (ms) => (t += ms); f.set = (v) => (t = v); return f; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const priced = (m = "") => [{ match: m, input_per_mtok: 1e6, output_per_mtok: 0 }];

// ---------- helpers ----------
function server(handler) {
  return new Promise((r) => { const s = http.createServer(handler); const c = s.close.bind(s); s.close = (...a) => { s.closeAllConnections(); return c(...a); }; s.listen(0, "127.0.0.1", () => r(s)); });
}
const portOf = (s) => s.address().port;
async function startProxy(policyOpts = {}, extra = {}) {
  const policy = P(policyOpts); const b = new Breaker(policy); const events = [];
  const px = createProxy({ policy, breaker: b, audit: (e, d) => events.push({ event: e, ...d }), ...extra });
  await new Promise((r) => px.listen(0, "127.0.0.1", r));
  return { px, b, events, port: portOf(px), close: () => { px.closeAllConnections(); px.close(); } };
}
function req(port, path, { method = "POST", body, headers = {} } = {}) {
  body ??= method === "POST" ? "{}" : "";
  return new Promise((res, rej) => {
    const r = http.request({ port, host: "127.0.0.1", path, method, headers }, (x) => {
      const bufs = []; x.on("data", (c) => bufs.push(c));
      x.on("end", () => res({ status: x.statusCode, headers: x.headers, body: Buffer.concat(bufs).toString() }));
      x.on("error", rej); x.on("aborted", () => res({ status: x.statusCode, aborted: true, body: Buffer.concat(bufs).toString() }));
    });
    r.on("error", rej); r.end(body);
  });
}
function raw(port, text, waitMs = 300) {
  return new Promise((res) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(text));
    let d = ""; s.on("data", (c) => (d += c)); s.on("error", () => {}); s.on("close", () => res(d));
    setTimeout(() => { s.destroy(); res(d); }, waitMs);
  });
}
function connect(port, target, extra = "") {
  return new Promise((res) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n${extra}`));
    let d = "";
    s.on("data", (c) => { d += c; res({ sock: s, get data() { return d; } }); });
    s.on("error", () => res({ sock: s, data: d }));
    setTimeout(() => res({ sock: s, data: d }), 1500);
  });
}
const echoServer = () => new Promise((r) => { const s = net.createServer((c) => c.pipe(c)); s.listen(0, "127.0.0.1", () => r(s)); });
const deadPort = async () => { const s = net.createServer(); await new Promise((r) => s.listen(0, "127.0.0.1", r)); const p = s.address().port; await new Promise((r) => s.close(r)); return p; };

// ===================== policy fuzz =====================
test("policy: wrong types and hostile values are rejected, not silently accepted", () => {
  const bad = [
    { pause_timeout_s: "5" }, { pause_timeout_s: Infinity }, { pause_timeout_s: 1e12 }, { pause_timeout_s: true }, { pause_timeout_s: 0 }, { pause_timeout_s: -1 },
    { workspace: 5 }, { workspace: "" }, { workspace: null },
    { upstreams: "abc" }, { upstreams: [] }, { upstreams: { x: "not a url" } }, { upstreams: { x: "file:///etc/passwd" } }, { upstreams: { "a/b": "https://x.io" } }, { upstreams: { x: 5 } },
    { egress: { mode: "enforce", alow: [] } }, { egress: { allow: "github.com" } }, { egress: [] }, { egress: { mode: "off" } },
    { prices: [{ match: "m", input_per_mtok: null, output_per_mtok: 1 }] },   // null >= 0 is true in JS: it would mean "free"
    { prices: [{ match: "m", input_per_mtok: "1", output_per_mtok: 1 }] },
    { prices: [{ match: "m", input_per_mtok: [], output_per_mtok: 1 }] },
    { prices: [{ match: "m", input_per_mtok: Infinity, output_per_mtok: 1 }] },
    { prices: [{ match: "m", input_per_mtok: -1, output_per_mtok: 1 }] }, { prices: {} }, { prices: [null] },
    { protected_paths: ".env" }, { ignore: [1] }, { notify_command: [] }, { notify_command: [1] },
    { limits: [] }, { limits: null }, { limits: { max_usd: Infinity } }, { limits: { max_usd: 0 } }, { limits: { max_usd: true } }, { limits: { max_usd: [] } },
  ];
  for (const b of bad) assert.throws(() => P(b), Error, JSON.stringify(b));
  assert.throws(() => P(JSON.parse('{"__proto__": {"on_trip":"kill"}}')), /unknown policy key/);
  assert.throws(() => P(JSON.parse('{"limits": {"__proto__": 1}}')), /unknown limit/);
  assert.equal({}.on_trip, undefined);
  for (const v of [null, 1, "s", true, undefined]) { if (v === undefined) continue; assert.throws(() => P(v), /object/); }
  assert.doesNotThrow(() => P({ limits: { max_usd: 1e-9 }, prices: [{ match: "", input_per_mtok: 0, output_per_mtok: 0 }], pause_timeout_s: 0.5 }));
});

test("policy: loadPolicy surfaces invalid JSON and missing file as errors", () => {
  const d = tmp(); writeFileSync(join(d, "p.json"), "{nope");
  assert.throws(() => loadPolicy(join(d, "p.json")));
  assert.throws(() => loadPolicy(join(d, "missing.json")));
  rmSync(d, { recursive: true });
});

// ===================== globs =====================
test("glob: '**/x' is a path component, not a suffix; 'a/**/b' matches a/b", () => {
  assert.ok(!globToRegExp("**/foo").test("barfoo"));
  assert.ok(globToRegExp("**/foo").test("a/b/foo"));
  assert.ok(globToRegExp("**/foo").test("foo"));
  assert.ok(globToRegExp("a/**/b").test("a/b"));
  assert.ok(globToRegExp("a/**/b").test("a/x/y/b"));
  assert.ok(!globToRegExp("a/**/b").test("a/xb"));
  assert.ok(globToRegExp("**").test("any/thing"));
  assert.ok(!globToRegExp("a?c").test("a/c"));
});

test("glob: file names containing newlines cannot dodge protected paths", () => {
  const b = new Breaker(P({}));
  b.addFsEvent("write", ".ssh/id\nrsa");
  assert.equal(b.state, "tripped");
  const b2 = new Breaker(P({}));
  b2.addFsEvent("write", "weird\ndir/.env");
  assert.equal(b2.state, "tripped");
});

test("glob: protected paths are case-insensitive (macOS file systems are)", () => {
  for (const p of [".ENV", ".Env.local", ".GIT/hooks/pre-commit", ".Ssh/id_rsa", ".MCP.json"]) {
    const b = new Breaker(P({})); b.addFsEvent("write", p);
    assert.equal(b.state, "tripped", p);
  }
});

test("glob: pathological '**' chains do not hang the matcher", () => {
  const t0 = Date.now();
  const re = globToRegExp("**/**/**/**/**/**/**/**/zzz");
  assert.ok(!re.test("a/".repeat(5000) + "y"));
  assert.ok(Date.now() - t0 < 2000);
});

// ===================== host matching =====================
test("hostMatches: userinfo, suffix confusion, punycode, trailing dots, IPv6, empty labels", () => {
  assert.ok(!hostMatches("allowed.com@evil.com", ["allowed.com"]));
  assert.ok(!hostMatches("evil.com@a.allowed.com", ["*.allowed.com"]));
  assert.ok(!hostMatches("evilallowed.com", ["*.allowed.com"]));
  assert.ok(!hostMatches("evilallowed.com", ["allowed.com"]));
  assert.ok(!hostMatches("allowed.com.evil.com", ["allowed.com"]));
  assert.ok(!hostMatches("..allowed.com", ["*.allowed.com"]));
  assert.ok(!hostMatches(".allowed.com", ["*.allowed.com"]));
  assert.ok(!hostMatches("allowed.com", ["*.allowed.com"]));
  assert.ok(hostMatches("a.b.allowed.com", ["*.allowed.com"]));
  assert.ok(hostMatches("ALLOWED.COM.", ["allowed.com"]));
  assert.ok(hostMatches("allowed.com", ["ALLOWED.COM."]), "trailing dot in the policy entry must not make it dead");
  assert.ok(hostMatches("bücher.de", ["xn--bcher-kva.de"]));
  assert.ok(hostMatches("xn--bcher-kva.de", ["bücher.de"]));
  assert.ok(!hostMatches("bücher.de", ["bucher.de"]));
  assert.ok(hostMatches("[::1]", ["::1"]));
  assert.ok(!hostMatches("::1", ["::2"]));
  assert.ok(!hostMatches("", [""]));
  assert.ok(!hostMatches("a b.com", ["a b.com"]));
  assert.ok(!hostMatches("evil.com/allowed.com", ["*.com"]));
});

// ===================== breaker accounting =====================
test("breaker: Infinity / NaN / string / huge / negative token counts", () => {
  const mk = (limits, prices) => new Breaker(P({ limits, prices }));
  let b = mk({ max_tokens: 1000 }, []);
  b.addUsage({ model: "x", input: Infinity });
  assert.equal(b.state, "tripped");
  assert.ok(Number.isFinite(b.tokens));
  b = mk({ max_usd: 1 }, [{ match: "", input_per_mtok: 0, output_per_mtok: 0 }]);   // price 0 * Infinity must not become NaN
  b.addUsage({ model: "x", input: Infinity, output: Infinity });
  assert.equal(b.usd, 0); assert.equal(b.state, "ok");
  b = mk({ max_usd: 1 }, priced());
  b.addUsage({ model: "x", input: Infinity });
  assert.equal(b.state, "tripped"); assert.ok(Number.isFinite(b.usd) || b.usd === Infinity);
  b = mk({ max_tokens: 100 }, []);
  b.addUsage({ model: "x", input: "60", output: "50" });       // numeric strings still count
  assert.equal(b.tokens, 110); assert.equal(b.state, "tripped");
  b = mk({ max_tokens: 100 }, []);
  for (const v of [NaN, -Infinity, -5, null, undefined, {}, [], "", "  ", "abc", true, 1e400]) b.addUsage({ model: "x", input: v, output: v });
  assert.ok(Number.isFinite(b.tokens) && b.tokens >= 0);
  b.addUsage();                                                  // no argument at all must not throw
});

test("breaker: limit exactly reached does not trip, one more does; trips only once; usage after trip still accounted", () => {
  const b = new Breaker(P({ limits: { max_tokens: 10 } }));
  let trips = 0; b.on("trip", () => trips++);
  b.addUsage({ input: 10 }); assert.equal(trips, 0);
  b.addUsage({ input: 1 }); assert.equal(trips, 1);
  b.addUsage({ input: 100 }); assert.equal(trips, 1);
  assert.equal(b.tokens, 111);
});

test("breaker: float accumulation does not trip early (0.1 * 10 is not > 1)", () => {
  const b = new Breaker(P({ limits: { max_usd: 1 }, prices: [{ match: "", input_per_mtok: 100_000, output_per_mtok: 0 }] }));
  for (let i = 0; i < 10; i++) b.addUsage({ input: 1 });   // 10 x $0.1
  assert.equal(b.state, "ok", `usd=${b.usd}`);
});

test("breaker: clock going backwards does not freeze windows or cause false trips", () => {
  const c = clock(10_000_000);
  const b = new Breaker(P({ limits: { max_requests_per_minute: 3 } }), c);
  b.addRequest(); b.addRequest();
  c.set(10_000_000 - 3_600_000);      // NTP step / VM restore: an hour into the past
  b.addRequest();                      // first observation of the jump: time is pinned, not reversed (3 in window, at the limit)
  c.adv(120_000);                      // two real minutes later
  b.addRequest(); b.addRequest();
  assert.equal(b.state, "ok", "old entries must expire; time keeps flowing forward");
  const c2 = clock(); c2.set(NaN);     // garbage clock must not throw
  assert.doesNotThrow(() => new Breaker(P({}), c2).addRequest());
});

test("breaker: window boundary is exact (entry exactly one minute old still counts, older does not)", () => {
  const c = clock();
  const b = new Breaker(P({ limits: { max_requests_per_minute: 1 } }), c);
  b.addRequest(); c.adv(60_000); b.addRequest();
  assert.equal(b.state, "tripped");
  const b2 = new Breaker(P({ limits: { max_requests_per_minute: 1 } }), c);
  b2.addRequest(); c.adv(60_001); b2.addRequest();
  assert.equal(b2.state, "ok");
});

test("breaker: price lookup is longest-prefix and case-insensitive; price 0 is a real price", () => {
  const b = new Breaker(P({ limits: { max_usd: 100 }, prices: [
    { match: "claude", input_per_mtok: 1, output_per_mtok: 1 },
    { match: "claude-opus", input_per_mtok: 15, output_per_mtok: 75 },
    { match: "free", input_per_mtok: 0, output_per_mtok: 0 },
  ] }));
  assert.equal(b.price("claude-opus-4").input_per_mtok, 15);
  assert.equal(b.price("CLAUDE-OPUS-4").input_per_mtok, 15);
  assert.equal(b.price("claude-haiku").input_per_mtok, 1);
  assert.equal(b.price("gpt-5"), null);
  b.addUsage({ model: "free-model", input: 1e9 });
  assert.deepEqual(b.stats().unpriced_models, []);
  b.addUsage({ model: "gpt-5", input: 1 });
  assert.deepEqual(b.stats().unpriced_models, ["gpt-5"]);
});

test("breaker: resume after a long pause gives a fresh runtime increment (no instant re-trip loop)", () => {
  const c = clock();
  const b = new Breaker(P({ limits: { max_runtime_minutes: 5 } }), c);
  c.adv(6 * 60_000); b.tick(); assert.equal(b.state, "tripped");
  c.adv(30 * 60_000);                 // human took 30 minutes to answer
  b.resume();
  b.tick(); assert.equal(b.state, "ok");
  c.adv(4 * 60_000); b.tick(); assert.equal(b.state, "ok");
  c.adv(2 * 60_000); b.tick(); assert.equal(b.state, "tripped");
});

test("breaker: resume() when not tripped is a no-op; hourly window slides across many entries", () => {
  const c = clock();
  const b = new Breaker(P({ limits: { max_usd_per_hour: 1 }, prices: priced() }), c);
  b.resume(); assert.equal(b.state, "ok");
  for (let i = 0; i < 1000; i++) { b.addUsage({ input: 0.0009 }); c.adv(5_000); }
  assert.equal(b.state, "ok"); // ~720 entries in the last hour at $0.0009 = $0.65
});

// ===================== UsageParser =====================
const SSE_LF = 'event: message_start\ndata: {"type":"message_start","message":{"model":"clé","usage":{"input_tokens":25,"cache_read_input_tokens":5,"output_tokens":1}}}\n\n'
  + 'event: ping\ndata: {"type":"ping"}\n\n'
  + 'data: {"type":"message_delta","usage":{"output_tokens":42}}\n\n'
  + 'data: {"type":"message_delta","usage":{"output_tokens":90}}\n\ndata: [DONE]\n\n';
test("UsageParser: SSE split at every byte boundary, LF / CRLF / CR, with a multibyte model name", () => {
  for (const nl of ["\n", "\r\n", "\r"]) {
    const buf = Buffer.from(SSE_LF.replaceAll("\n", nl));
    for (let i = 0; i <= buf.length; i++) {
      const p = new UsageParser("text/event-stream");
      p.push(buf.subarray(0, i)); p.push(buf.subarray(i));
      assert.deepEqual(p.finish("text/event-stream"), { model: "clé", input: 30, output: 90 }, `split ${i} nl=${JSON.stringify(nl)}`);
    }
    const p = new UsageParser("text/event-stream");           // one byte at a time
    for (const byte of buf) p.push(Buffer.from([byte]));
    assert.deepEqual(p.finish(), { model: "clé", input: 30, output: 90 });
  }
});

test("UsageParser: multi-line data fields, no-space 'data:', comments, unterminated last event, missing blank lines", () => {
  let p = new UsageParser("text/event-stream");
  p.push('data: {"model":"m",\ndata: "usage":{"input_tokens":3,\ndata: "output_tokens":4}}\n\n');
  assert.deepEqual(p.finish(), { model: "m", input: 3, output: 4 });
  p = new UsageParser("text/event-stream");
  p.push(': keepalive\ndata:{"usage":{"input_tokens":1,"output_tokens":2}}');   // no trailing newline at all
  assert.deepEqual(p.finish(), { model: null, input: 1, output: 2 });
  p = new UsageParser("text/event-stream");
  p.push('data: {"usage":{"input_tokens":5}}\ndata: {"usage":{"output_tokens":6}}\n');   // sloppy server: no blank lines
  assert.deepEqual(p.finish(), { model: null, input: 5, output: 6 });
});

test("UsageParser: OpenAI Responses API (usage nested under response), chat chunks, [DONE], malformed JSON", () => {
  let p = new UsageParser("text/event-stream");
  p.push('data: {"type":"response.created","response":{"model":"gpt-x","usage":null}}\n\ndata: {"type":"response.completed","response":{"model":"gpt-x","usage":{"input_tokens":11,"output_tokens":7}}}\n\n');
  assert.deepEqual(p.finish(), { model: "gpt-x", input: 11, output: 7 });
  p = new UsageParser("text/event-stream");
  p.push('data: {broken\n\ndata: [DONE]\n\ndata: {"model":"g","usage":{"prompt_tokens":2,"completion_tokens":3}}\n\n');
  assert.deepEqual(p.finish(), { model: "g", input: 2, output: 3 });
});

test("UsageParser: string numbers are not concatenated ('5' + 0 === '50'), negatives/NaN ignored", () => {
  const p = new UsageParser(); p.push('{"usage":{"input_tokens":"5","output_tokens":-3,"cache_read_input_tokens":"7"}}');
  assert.deepEqual(p.finish("application/json"), { model: null, input: 0, output: 0 });
  const q = new UsageParser(); q.push('{"usage":{"input_tokens":null,"prompt_tokens":4,"output_tokens":1e999}}');
  const r = q.finish(""); assert.ok(Number.isFinite(r.input) && Number.isFinite(r.output));
});

test("UsageParser: binary, empty, deeply nested and huge junk never throw", () => {
  for (const ct of ["application/json", "text/event-stream", "", "application/octet-stream"]) {
    for (const body of [Buffer.alloc(0), Buffer.from([0xff, 0xfe, 0x00, 0x80]), crypto.getRandomValues(Buffer.alloc(5000)), Buffer.from("[".repeat(100000)), Buffer.from("data: " + "{".repeat(100000))]) {
      const p = new UsageParser(ct); p.push(body);
      assert.doesNotThrow(() => p.finish(ct));
    }
  }
});

test("UsageParser: a multi-megabyte SSE stream keeps bounded memory AND still counts the input tokens from the first event", () => {
  const p = new UsageParser("text/event-stream");
  p.push('data: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":1234,"output_tokens":1}}}\n\n');
  const filler = 'data: {"type":"content_block_delta","delta":{"text":"' + "x".repeat(900) + '"}}\n\n';
  let max = 0;
  for (let i = 0; i < 6000; i++) { p.push(filler); max = Math.max(max, p.buf.length + p.rem.length); }
  p.push('data: {"type":"message_delta","usage":{"output_tokens":77}}\n\n');
  assert.ok(max < 300_000, `buffered ${max}`);
  assert.deepEqual(p.finish(), { model: "m", input: 1234, output: 77 });
});

test("UsageParser: a JSON body over the cap still yields usage (it used to read 0 tokens = free)", () => {
  const body = '{"model":"big","content":"' + "x".repeat(6 * 1024 * 1024) + '","usage":{"input_tokens":7,"output_tokens":9}}';
  const p = new UsageParser("application/json");
  for (let i = 0; i < body.length; i += 65536) p.push(body.slice(i, i + 65536));
  assert.deepEqual(p.finish(), { model: "big", input: 7, output: 9 });
});

// ===================== proxy: reverse =====================
test("proxy: '//host' and '/\\host' paths cannot redirect the upstream request (credential exfiltration)", async () => {
  let evilHits = 0, evilHeaders = null;
  const evil = await server((q, s) => { evilHits++; evilHeaders = q.headers; q.resume(); s.end("pwn"); });
  const up = await server((q, s) => { q.resume(); s.end("{}"); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  const e = portOf(evil);
  for (const path of [`/anthropic//127.0.0.1:${e}/steal`, `/anthropic/\\127.0.0.1:${e}/steal`, `/anthropic///127.0.0.1:${e}/`, `/anthropic//localhost:${e}/x`, `/anthropic/\\\\localhost:${e}/x`]) {
    const r = await req(t.port, path, { headers: { "x-api-key": "sk-secret" } });
    assert.equal(r.status, 400, path);
  }
  assert.equal(evilHits, 0, "the evil host must never be contacted");
  assert.equal((await req(t.port, "/anthropic/v1/messages")).status, 200);
  assert.equal((await req(t.port, "/anthropic/../openai/x")).status, 200);   // dot-segments stay on the upstream origin
  t.close(); up.close(); evil.close();
});

test("proxy: hop-by-hop and proxy credentials are not forwarded; Host is rewritten; encoding forced to identity", async () => {
  let seen = null;
  const up = await server((q, s) => { seen = q.headers; q.resume(); s.end("{}"); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  await req(t.port, "/anthropic/v1/x", { headers: { connection: "x-private, keep-alive", "x-private": "1", "proxy-authorization": "Basic Zm9v", te: "trailers", "accept-encoding": "gzip, br", host: "attacker.example", "x-keep": "yes", authorization: "Bearer sk-test" } });
  assert.equal(seen["x-private"], undefined);
  assert.equal(seen["proxy-authorization"], undefined);
  assert.equal(seen.te, undefined);
  assert.equal(seen["x-keep"], "yes");
  assert.equal(seen.authorization, "Bearer sk-test");
  assert.equal(seen["accept-encoding"], "identity");
  assert.equal(seen.host, `127.0.0.1:${portOf(up)}`);
  t.close(); up.close();
});

test("proxy: gzip / deflate / br responses are decompressed for accounting (compression used to hide all usage)", async () => {
  const body = JSON.stringify({ model: "m", usage: { input_tokens: 100, output_tokens: 50 } });
  for (const [enc, fn] of [["gzip", zlib.gzipSync], ["deflate", zlib.deflateSync], ["br", zlib.brotliCompressSync]]) {
    const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "application/json", "content-encoding": enc }); s.end(fn(body)); });
    const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, limits: { max_tokens: 1000 } });
    const r = await req(t.port, "/anthropic/v1/messages", { headers: { "accept-encoding": enc } });
    assert.equal(r.status, 200);
    assert.equal(r.headers["content-encoding"], enc, "client still receives the encoded body untouched");
    await sleep(50);
    assert.equal(t.b.tokens, 150, enc);
    t.close(); up.close();
  }
});

test("proxy: SSE streamed in tiny chunks with CRLF; usage counted once from the cumulative events", async () => {
  const sse = SSE_LF.replaceAll("\n", "\r\n");
  const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "text/event-stream" }); let i = 0; const iv = setInterval(() => { if (i >= sse.length) { clearInterval(iv); s.end(); } else { s.write(sse.slice(i, i + 7)); i += 7; } }, 1); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, prices: priced() });
  const r = await req(t.port, "/anthropic/v1/messages");
  assert.equal(r.body, sse);
  await sleep(30);
  assert.equal(t.b.tokens, 120);   // 25 + 5 cache + 90 out
  assert.equal(t.events.filter((e) => e.event === "usage").length, 1);
  t.close(); up.close();
});

test("proxy: upstream dying mid-stream still counts what was seen, and does not crash or hang the client", async () => {
  const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "text/event-stream" }); s.write('data: {"type":"message_start","message":{"model":"m","usage":{"input_tokens":500,"output_tokens":1}}}\n\n'); setTimeout(() => s.destroy(), 50); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  const r = await Promise.race([req(t.port, "/anthropic/v1/messages").catch(() => ({ status: "reset" })), sleep(3000).then(() => "HUNG")]);
  assert.notEqual(r, "HUNG");
  await sleep(100);
  assert.equal(t.b.tokens, 501);
  assert.equal((await req(t.port, "/nope/x")).status, 404);   // proxy still serving
  t.close(); up.close();
});

test("proxy: upstream that accepts but never answers is cut off by the idle timeout (no leaked sockets)", async () => {
  let open = 0;
  const up = await server((q, s) => { open++; q.resume(); s.on("close", () => open--); /* never respond */ });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } }, { upstreamIdleMs: 200 });
  const r = await Promise.race([req(t.port, "/anthropic/v1/m"), sleep(3000).then(() => "HUNG")]);
  assert.notEqual(r, "HUNG"); assert.equal(r.status, 504);
  await sleep(100); assert.equal(open, 0);
  t.close(); up.close();
});

test("proxy: client aborting an upload half way destroys the upstream request", async () => {
  let upClosed = false;
  const up = await server((q, s) => { q.on("data", () => {}); q.on("close", () => (upClosed = true)); s.on("close", () => (upClosed = true)); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  await new Promise((r) => { const c = net.connect(t.port, "127.0.0.1", () => { c.write("POST /anthropic/v1/m HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc"); setTimeout(() => { c.destroy(); r(); }, 100); }); });
  await sleep(300);
  assert.ok(upClosed, "upstream request must be torn down");
  t.close(); up.close();
});

test("proxy: upstream down -> 502, client survives; HEAD and OPTIONS and Expect: 100-continue work", async () => {
  const dead = await deadPort();
  let t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${dead}` } });
  assert.equal((await req(t.port, "/anthropic/v1/m")).status, 502);
  t.close();
  const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "application/json", allow: "GET" }); s.end(q.method === "HEAD" ? undefined : "{}"); });
  t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  assert.equal((await req(t.port, "/anthropic/x", { method: "HEAD", body: undefined })).status, 200);
  assert.equal((await req(t.port, "/anthropic/x", { method: "OPTIONS" })).status, 200);
  const r = await raw(t.port, "POST /anthropic/x HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", 1000);
  assert.match(r, /100 Continue/); assert.match(r, /200 OK/);
  t.close(); up.close();
});

test("proxy: request smuggling (CL+TE, dup CL, obs-fold) never reaches upstream as a second request", async () => {
  const seen = [];
  const up = await server((q, s) => { seen.push(q.url); q.resume(); s.end("{}"); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` } });
  const smuggled = "GET /anthropic/SMUGGLED HTTP/1.1\r\nHost: x\r\n\r\n";
  await raw(t.port, `POST /anthropic/a HTTP/1.1\r\nHost: x\r\nContent-Length: ${4 + smuggled.length}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n${smuggled}`, 400);
  await raw(t.port, `POST /anthropic/b HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: ${smuggled.length}\r\n\r\n${smuggled}`, 400);
  await raw(t.port, `POST /anthropic/c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n Transfer-Encoding: x\r\n\r\n0\r\n\r\n${smuggled}`, 400);
  assert.ok(!seen.some((u) => u.includes("SMUGGLED")), JSON.stringify(seen));
  assert.equal((await req(t.port, "/anthropic/ok")).status, 200);
  t.close(); up.close();
});

test("proxy: oversized headers and garbage on the socket do not crash it", async () => {
  const t = await startProxy({});
  const r = await raw(t.port, `GET /anthropic/x HTTP/1.1\r\nHost: x\r\nX-Big: ${"a".repeat(100_000)}\r\n\r\n`, 400);
  assert.ok(!r.includes("200 OK"));
  await raw(t.port, "\x00\x01\x02garbage\r\n\r\n", 200);
  await raw(t.port, "GET HTTP/1.1\r\n\r\n", 200);
  assert.equal((await req(t.port, "/nope")).status, 404);
  t.close();
});

test("proxy: 60 concurrent requests are all counted exactly", async () => {
  const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "application/json" }); setTimeout(() => s.end(JSON.stringify({ model: "m", usage: { input_tokens: 10, output_tokens: 5 } })), Math.random() * 30); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, limits: { max_requests_per_minute: 1000 } });
  const rs = await Promise.all(Array.from({ length: 60 }, () => req(t.port, "/anthropic/v1/m")));
  assert.ok(rs.every((r) => r.status === 200));
  await sleep(50);
  assert.equal(t.b.tokens, 900);
  t.close(); up.close();
});

test("proxy: authorization material never appears in audit events (reverse, forward, CONNECT)", async () => {
  const up = await server((q, s) => { q.resume(); s.end("{}"); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, egress: { mode: "log" } });
  const h = { authorization: "Bearer sk-TOPSECRET", "x-api-key": "sk-TOPSECRET", "proxy-authorization": "Basic TOPSECRET", cookie: "s=TOPSECRET" };
  await req(t.port, "/anthropic/v1/m?key=1", { headers: h });
  await req(t.port, `http://127.0.0.1:${portOf(up)}/p`, { headers: h });
  await raw(t.port, `CONNECT 127.0.0.1:${await deadPort()} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic TOPSECRET\r\n\r\n`, 300);
  await req(t.port, "http://blocked.example/x", { headers: h });
  assert.ok(t.events.length >= 3);
  assert.ok(!JSON.stringify(t.events).includes("TOPSECRET"));
  t.close(); up.close();
});

test("proxy: oversized upload through the reverse proxy trips the upload cap", async () => {
  const up = await server((q, s) => { q.resume(); q.on("end", () => s.end("{}")); });
  const t = await startProxy({ upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, limits: { max_upload_mb: 1 } });
  await req(t.port, "/anthropic/v1/m", { body: Buffer.alloc(2 * 1048576) });
  assert.equal(t.b.state, "tripped");
  t.close(); up.close();
});

// ===================== proxy: forward + CONNECT =====================
test("proxy forward: non-http absolute URLs are refused (https:// to an allowed host used to crash the process)", async () => {
  const t = await startProxy({ egress: { mode: "enforce", allow: ["allowed.example"] } });
  for (const u of ["https://allowed.example/x", "ftp://allowed.example/x", "file:///etc/passwd", "ws://allowed.example/", "gopher://allowed.example/"]) {
    const r = await req(t.port, u, { method: "GET", body: undefined });
    assert.equal(r.status, 400, u);
  }
  assert.equal((await req(t.port, "http://allowed.example@evil.example/x", { method: "GET", body: undefined })).status, 403);
  assert.equal((await req(t.port, "http://evilallowed.example/x", { method: "GET", body: undefined })).status, 403);
  assert.equal((await req(t.port, "http://allowed.example.evil.example/x", { method: "GET", body: undefined })).status, 403);
  assert.equal((await req(t.port, "/nope")).status, 404);
  t.close();
});

test("proxy forward: Host header is rewritten to the vetted host (no domain fronting through an allowed address)", async () => {
  let seen = null;
  const sink = await server((q, s) => { seen = q.headers; q.resume(); s.end("ok"); });
  const t = await startProxy({ egress: { mode: "enforce", allow: ["127.0.0.1"] } });
  await req(t.port, `http://127.0.0.1:${portOf(sink)}/x`, { method: "GET", body: undefined, headers: { host: "evil.example", "proxy-authorization": "Basic Zm9v" } });
  assert.equal(seen.host, `127.0.0.1:${portOf(sink)}`);
  assert.equal(seen["proxy-authorization"], undefined);
  t.close(); sink.close();
});

test("CONNECT: bad ports/hosts get 400 instead of crashing the proxy", async () => {
  const t = await startProxy({ egress: { mode: "log" } });   // log mode: nothing blocks, so validation is the only defence
  for (const target of ["127.0.0.1:99999", "127.0.0.1:0", "127.0.0.1:65536", "a@b:80", "a b:80", ":80", "[::1:80", "[]:80", "host..x:80", "-bad:80", "x/y:80"]) {
    const r = await connect(t.port, target);
    assert.match(r.data, /^HTTP\/1\.1 400/, target);
  }
  assert.equal((await req(t.port, "/nope")).status, 404);
  t.close();
});

test("CONNECT: allowlist normalisation (case, trailing dot, punycode, userinfo, wildcard suffix)", async () => {
  const echo = await echoServer(); const p = portOf(echo);
  const t = await startProxy({ egress: { mode: "enforce", allow: ["127.0.0.1", "*.allowed.example", "xn--bcher-kva.example"] } });
  let r = await connect(t.port, `127.0.0.1:${p}`); assert.match(r.data, /^HTTP\/1\.1 200/); r.sock.destroy();
  for (const bad of ["evilallowed.example:443", "allowed.example:443", "x@a.allowed.example:443", "allowed.example.evil.example:443", "a.allowed.example@evil.example:443", "127.0.0.2:443"]) {
    r = await connect(t.port, bad); assert.match(r.data, /^HTTP\/1\.1 (403|400)/, bad);
  }
  // allowed by normalisation but unresolvable/unreachable: must be 502 (past the allowlist), never 403
  const dead = await deadPort();
  r = await connect(t.port, `127.0.0.1.:${dead}`); assert.match(r.data, /^HTTP\/1\.1 502/);
  t.close(); echo.close();
});

test("CONNECT: data sent right behind the CONNECT line is forwarded, tunnels work both ways", async () => {
  const echo = await echoServer();
  const t = await startProxy({ egress: { mode: "enforce", allow: ["127.0.0.1"] } });
  const r = await new Promise((res) => {
    const s = net.connect(t.port, "127.0.0.1", () => s.write(`CONNECT 127.0.0.1:${portOf(echo)} HTTP/1.1\r\nHost: x\r\n\r\nPING`));
    let d = ""; s.on("data", (c) => { d += c; if (d.includes("PING")) { s.destroy(); res(d); } }); setTimeout(() => res(d), 1500);
  });
  assert.match(r, /200 Connection Established\r\n\r\nPING/);
  t.close(); echo.close();
});

test("CONNECT: the per-tunnel trip listener is removed when the tunnel closes (it used to leak one per tunnel)", async () => {
  const echo = await echoServer();
  const t = await startProxy({ egress: { mode: "enforce", allow: ["127.0.0.1"] } });
  const base = t.b.listenerCount("trip");
  for (let i = 0; i < 25; i++) { const r = await connect(t.port, `127.0.0.1:${portOf(echo)}`); r.sock.destroy(); }
  await sleep(200);
  assert.equal(t.b.listenerCount("trip"), base);
  // and an open tunnel is cut when the breaker trips
  const r = await connect(t.port, `127.0.0.1:${portOf(echo)}`);
  const closed = new Promise((res) => r.sock.on("close", () => res(true)));
  t.b.trip("test", 1, 2);
  assert.equal(await Promise.race([closed, sleep(1000).then(() => false)]), true);
  t.close(); echo.close();
});

test("CONNECT: frozen breaker refuses new tunnels", async () => {
  const t = await startProxy({});
  t.b.trip("x", 1, 2);
  assert.match((await connect(t.port, "api.anthropic.com:443")).data, /^HTTP\/1\.1 503/);
  t.close();
});

// ===================== fswatch =====================
test("fswatch: rewriting a file with the same size and a restored mtime is still detected (ctime)", () => {
  const d = tmp();
  writeFileSync(join(d, ".env"), "AAAA");
  const old = new Date("2020-01-01T00:00:00Z"); utimesSync(join(d, ".env"), old, old);
  const s1 = snapshot(d, () => false);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);   // ctime granularity is the kernel tick
  writeFileSync(join(d, ".env"), "BBBB"); utimesSync(join(d, ".env"), old, old);
  assert.deepEqual(diff(s1, snapshot(d, () => false)).writes, [".env"]);
  rmSync(d, { recursive: true });
});

test("fswatch: a tree larger than the snapshot cap is flagged, and never produces phantom deletions", () => {
  const d = tmp();
  for (let i = 0; i < 30; i++) writeFileSync(join(d, `f${i}`), "x");
  const full = snapshot(d, () => false);
  const part = snapshot(d, () => false, 10);
  assert.equal(part.truncated, true); assert.equal(full.truncated, undefined);
  assert.deepEqual(diff(full, part).deletes, []);
  assert.deepEqual(diff(part, full).deletes, []);
  const ev = [];
  const b = new Breaker(P({}));
  const m = new FsMonitor({ root: d, breaker: b, audit: (e) => ev.push(e), maxEntries: 10 });
  m.poll(); m.poll();
  assert.equal(ev.filter((e) => e === "fs_truncated").length, 1);
  assert.equal(b.state, "ok");
  rmSync(d, { recursive: true });
});

test("fswatch: symlinks are lstat'ed (not followed); dangling and looping symlinks do not hang or throw", () => {
  const d = tmp(); const outside = tmp("abo-");
  writeFileSync(join(outside, "secret"), "x");
  symlinkSync(outside, join(d, "link")); symlinkSync("nowhere", join(d, "dangling")); symlinkSync(".", join(d, "loop"));
  const s = snapshot(d, () => false);
  assert.deepEqual([...s.keys()].sort(), ["dangling", "link", "loop"]);
  rmSync(d, { recursive: true }); rmSync(outside, { recursive: true });
});

test("fswatch: file written via a symlink to .env trips the protected path (the target's metadata changes)", () => {
  const d = tmp();
  writeFileSync(join(d, ".env"), "A"); symlinkSync(".env", join(d, "innocent"));
  const b = new Breaker(P({ workspace: d }));
  const ev = [];
  const m = new FsMonitor({ root: d, breaker: b, audit: (e) => ev.push(e) });
  writeFileSync(join(d, "innocent"), "BB");
  m.poll();
  assert.equal(b.state, "tripped");
  rmSync(d, { recursive: true });
});

test("fswatch: wide and deep trees are handled", () => {
  const d = tmp();
  let p = d; for (let i = 0; i < 60; i++) { p = join(p, "d"); mkdirSync(p); }
  writeFileSync(join(p, "leaf"), "x");
  for (let i = 0; i < 2000; i++) writeFileSync(join(d, `w${i}`), "");
  const s = snapshot(d, () => false);
  assert.equal(s.size, 2001);
  rmSync(d, { recursive: true });
});

// ===================== audit =====================
test("audit: a second run appends to the same log and the chain still verifies (it used to restart at genesis)", () => {
  const d = tmp(); const f = join(d, "sub/a.jsonl");
  let a = new AuditLog(f); a.write("one"); a.write("two"); a.close();
  a = new AuditLog(f); a.write("three"); a.close();
  assert.deepEqual(verifyChain(readFileSync(f, "utf8")), { ok: true, lines: 3 });
  rmSync(d, { recursive: true });
});

test("audit: caller data cannot overwrite the chain fields", () => {
  const d = tmp(); const f = join(d, "a.jsonl");
  const a = new AuditLog(f); a.write("one"); a.write("two", { prev: "x", event: "fake" }); a.close();
  assert.equal(verifyChain(readFileSync(f, "utf8")).ok, true);
  assert.equal(JSON.parse(readFileSync(f, "utf8").trim().split("\n")[1]).event, "two");
  rmSync(d, { recursive: true });
});

test("audit: refuses to append through a symlink planted at the log path", () => {
  const d = tmp(); writeFileSync(join(d, "victim"), "keep\n"); symlinkSync(join(d, "victim"), join(d, "a.jsonl"));
  assert.throws(() => new AuditLog(join(d, "a.jsonl")), /ELOOP|symbolic|EMLINK/i);
  assert.equal(readFileSync(join(d, "victim"), "utf8"), "keep\n");
  rmSync(d, { recursive: true });
});

test("audit: tamper matrix (edit, delete, reorder, append forged, invalid JSON, null/array lines, empty, truncation)", () => {
  const d = tmp(); const f = join(d, "a.jsonl");
  const a = new AuditLog(f); for (const e of ["a", "b", "c", "d"]) a.write(e, { n: 1 }); const head = a.head; a.close();
  const txt = readFileSync(f, "utf8"); const L = txt.trim().split("\n");
  const j = (arr) => arr.join("\n") + "\n";
  assert.equal(verifyChain(txt, { expectHead: head }).ok, true);
  assert.equal(chainHead(txt), head);
  assert.equal(verifyChain(j([L[0], L[1].replace('"n":1', '"n":2'), L[2], L[3]])).ok, false);   // edit
  assert.equal(verifyChain(j([L[0], L[2], L[3]])).ok, false);                                   // delete middle
  assert.equal(verifyChain(j([L[1], L[0], L[2], L[3]])).ok, false);                             // reorder
  assert.equal(verifyChain(j([L[1], L[2], L[3]])).ok, false);                                   // delete first
  assert.equal(verifyChain(txt + '{"t":"x","event":"forged","prev":"deadbeef"}\n').ok, false);  // appended, wrong prev
  assert.equal(verifyChain(txt + "{not json\n").ok, false);
  for (const junk of ["null", "123", '"str"', "[]", "true"]) assert.equal(verifyChain(junk + "\n").ok, false, junk);   // must not throw
  assert.equal(verifyChain(txt.replace("\n", "\r\n")).ok, false);
  // honest limits:
  assert.equal(verifyChain(j(L.slice(0, 3))).ok, true, "tail truncation is NOT detectable from the log alone");
  assert.equal(verifyChain(j(L.slice(0, 3)), { expectHead: head }).ok, false, "...but is detected against a stored head hash");
  assert.equal(verifyChain("").ok, true);                                                        // empty verifies vacuously (the CLI flags it)
  assert.equal(verifyChain("\n\n\n", { expectHead: head }).ok, false);
  rmSync(d, { recursive: true });
});

// ===================== run / process control =====================
function sandbox(extra = {}) { const d = tmp("abrun-"); return { d, policy: P({ workspace: d, ...extra }) }; }
const dead = (pid) => { try { process.kill(pid, 0); return false; } catch (e) { return e.code === "ESRCH"; } };

test("run: exit code propagation (0, nonzero, signal death uses the real signal number)", async () => {
  for (const [script, want] of [["process.exit(0)", 0], ["process.exit(3)", 3], ["process.kill(process.pid,'SIGSEGV')", 128 + 11], ["process.kill(process.pid,'SIGTERM')", 128 + 15], ["process.kill(process.pid,'SIGABRT')", 128 + 6]]) {
    const { d, policy } = sandbox();
    const code = await Promise.race([run({ policy, argv: [NODE, "-e", script], ask: async () => "kill", out: () => {} }), sleep(8000).then(() => "HUNG")]);
    assert.equal(code, want, script);
    rmSync(d, { recursive: true, force: true });
  }
});

test("run: missing / non-executable command reports why and returns 127 without hanging", async () => {
  const { d, policy } = sandbox(); const out = [];
  const code = await Promise.race([run({ policy, argv: ["/nonexistent/agent"], ask: async () => "kill", out: (s) => out.push(s) }), sleep(5000).then(() => "HUNG")]);
  assert.equal(code, 127); assert.match(out.join(""), /cannot start/);
  writeFileSync(join(d, "noexec"), "#!/bin/sh\n"); 
  assert.equal(await Promise.race([run({ policy, argv: [join(d, "noexec")], ask: async () => "kill", out: () => {} }), sleep(5000).then(() => "HUNG")]), 127);
  rmSync(d, { recursive: true, force: true });
});

test("run: two runs in one workspace leave a verifiable audit log; signal listeners are not leaked", async () => {
  const { d, policy } = sandbox();
  const before = ["SIGINT", "SIGTERM", "SIGHUP", "uncaughtException", "unhandledRejection"].map((s) => process.listenerCount(s));
  await run({ policy, argv: [NODE, "-e", "0"], ask: async () => "kill", out: () => {} });
  await run({ policy, argv: [NODE, "-e", "process.exit(2)"], ask: async () => "kill", out: () => {} });
  assert.deepEqual(["SIGINT", "SIGTERM", "SIGHUP", "uncaughtException", "unhandledRejection"].map((s) => process.listenerCount(s)), before);
  const r = verifyChain(readFileSync(join(d, ".agentbreaker/audit.jsonl"), "utf8"));
  assert.equal(r.ok, true); assert.ok(r.lines >= 4);
  rmSync(d, { recursive: true, force: true });
});

test("run: a nonexistent notify_command does not crash (unhandled 'error' event) and the trip is still handled", async () => {
  const { d, policy } = sandbox({ on_trip: "kill", notify_command: ["/nonexistent/notify-xyz"] });
  const code = await Promise.race([run({ policy, argv: [NODE, "-e", `require('fs').writeFileSync('.env','x');setTimeout(()=>{},60000)`], pollMs: 50, ask: async () => "kill", out: () => {} }), sleep(8000).then(() => "HUNG")]);
  assert.equal(code, 137);
  rmSync(d, { recursive: true, force: true });
});

test("run: child that ignores SIGTERM and SIGINT is still killed on trip (SIGKILL), including while frozen", async () => {
  for (const on_trip of ["kill", "pause"]) {
    const { d, policy } = sandbox({ on_trip });
    const script = `process.on('SIGTERM',()=>{});process.on('SIGINT',()=>{});require('fs').writeFileSync('.env','x');setInterval(()=>{},1000)`;
    const code = await Promise.race([run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async () => "kill", out: () => {} }), sleep(8000).then(() => "HUNG")]);
    assert.equal(code, 137, on_trip);
    rmSync(d, { recursive: true, force: true });
  }
});

test("run: SIGTERM delivered to agentbreaker while the agent is frozen terminates the agent (SIGCONT is sent too)", async () => {
  const { d, policy } = sandbox({ pause_timeout_s: 60 });
  const script = `require('fs').writeFileSync('.env','x');setInterval(()=>{},1000)`;
  const p = run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: () => new Promise(() => {}), out: () => {} });
  await sleep(600);                                    // tripped and frozen by now
  process.emit("SIGTERM");
  const code = await Promise.race([p, sleep(6000).then(() => "HUNG")]);
  assert.equal(code, 128 + 15);
  rmSync(d, { recursive: true, force: true });
});

test("run: grandchildren are frozen with the agent and killed with it; instantly-exiting child leaves no stragglers", async () => {
  const { d, policy } = sandbox({ pause_timeout_s: 30 });
  const script = `const cp=require('child_process');const fs=require('fs');
    const c=cp.spawn(process.execPath,['-e',"const fs=require('fs');let i=0;setInterval(()=>fs.writeFileSync('gtick',String(i++)),20)"],{stdio:'ignore'});
    fs.writeFileSync('gc',String(c.pid));setTimeout(()=>fs.writeFileSync('.env','x'),400);setInterval(()=>{},1000)`;
  let frozen = null;
  const code = await run({ policy, argv: [NODE, "-e", script], pollMs: 50, out: () => {}, ask: async () => {
    await sleep(150); const a = readFileSync(join(d, "gtick"), "utf8"); await sleep(300); frozen = a === readFileSync(join(d, "gtick"), "utf8"); return "kill";
  } });
  assert.equal(frozen, true, "the whole process group must be stopped, not just the leader");
  assert.equal(code, 137);
  await sleep(200);
  assert.ok(dead(Number(readFileSync(join(d, "gc"), "utf8"))));
  rmSync(d, { recursive: true, force: true });
});

test("run: if agentbreaker's own handler throws (e.g. disk full while reporting), the agent is killed, not left running", async () => {
  const { d, policy } = sandbox({ on_trip: "kill" });
  const script = `require('fs').writeFileSync('pid',String(process.pid));require('fs').writeFileSync('.env','x');setInterval(()=>{},1000)`;
  const code = await Promise.race([run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async () => "kill", out: (s) => { if (s.includes("TRIPPED")) throw new Error("boom"); } }), sleep(8000).then(() => "HUNG")]);
  assert.equal(code, 137);
  rmSync(d, { recursive: true, force: true });
});

test("run: refuses an audit log path that is a symlink (and does not start the agent)", async () => {
  const { d, policy } = sandbox();
  mkdirSync(join(d, ".agentbreaker")); writeFileSync(join(d, "victim"), "keep");
  symlinkSync(join(d, "victim"), join(d, ".agentbreaker/audit.jsonl"));
  await assert.rejects(run({ policy, argv: [NODE, "-e", "require('fs').writeFileSync('started','1')"], ask: async () => "kill", out: () => {} }));
  assert.ok(!existsSync(join(d, "started")));
  assert.equal(readFileSync(join(d, "victim"), "utf8"), "keep");
  rmSync(d, { recursive: true, force: true });
});

test("run: real agent through the real proxy; unparsed gzip is not a loophole; end-to-end spend trip", async () => {
  const body = zlib.gzipSync(JSON.stringify({ model: "m", usage: { input_tokens: 2_000_000, output_tokens: 0 } }));
  const up = await server((q, s) => { q.resume(); s.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" }); s.end(body); });
  const { d, policy } = sandbox({ on_trip: "kill", upstreams: { anthropic: `http://127.0.0.1:${portOf(up)}` }, limits: { max_usd: 1 }, prices: [{ match: "m", input_per_mtok: 1, output_per_mtok: 0 }] });
  const script = `const http=require('http');const u=new URL(process.env.ANTHROPIC_BASE_URL);
    const go=()=>new Promise(r=>{const q=http.request({host:u.hostname,port:u.port,path:'/anthropic/v1/messages',method:'POST',headers:{'accept-encoding':'gzip'}},x=>{x.resume();x.on('end',r)});q.on('error',r);q.end('{}')});
    (async()=>{await go();await go();await go();setInterval(()=>{},1000)})()`;
  const code = await Promise.race([run({ policy, argv: [NODE, "-e", script], ask: async () => "kill", out: () => {} }), sleep(10000).then(() => "HUNG")]);
  assert.equal(code, 137);
  assert.match(readFileSync(join(d, ".agentbreaker/audit.jsonl"), "utf8"), /spend limit reached/);
  up.close(); rmSync(d, { recursive: true, force: true });
});

// ===================== CLI =====================
function cli(args, { cwd, input, timeout = 15000 } = {}) {
  return spawnSync(NODE, [CLI, ...args], { cwd, input: input ?? "", encoding: "utf8", timeout, env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", NODE_OPTIONS: "--disable-warning=UNDICI-EHPA" } });
}

test("cli: argument fuzzing returns clean usage errors (never a stack trace, never silently defaults)", () => {
  const d = tmp();
  const cases = [
    [[], 2], [["--help"], 0], [["-h"], 0], [["bogus"], 2], [["run"], 2], [["run", "--"], 2], [["run", "--policy"], 2],
    [["run", "--policy", "--", "echo"], 2],   // "--" consumed as the value would silently use defaults
    [["run", "--on-trip"], 2], [["run", "--on-trip", "--", "echo"], 2], [["run", "--on-trip", "explode", "--", "echo", "x"], 2],
    [["run", "--wat", "--", "echo"], 2], [["run", "--policy", "/nonexistent.json", "--", "echo"], 2], [["run", "echo", "hi"], 2],
    [["init", "a", "b"], 2], [["init", "--force"], 2],
    [["verify-log", "--head"], 2], [["verify-log", "--head", "zz"], 2], [["verify-log", "--bogus"], 2], [["verify-log", "a", "b"], 2], [["verify-log", "/nonexistent"], 1],
  ];
  for (const [args, want] of cases) {
    const r = cli(args, { cwd: d });
    assert.equal(r.status, want, `${args.join(" ")} -> ${r.status} ${r.stderr}`);
    assert.ok(!/\n\s+at /.test(r.stderr), `stack trace for ${args.join(" ")}`);
  }
  rmSync(d, { recursive: true });
});

test("cli: init writes a loadable policy and refuses to overwrite; verify-log exit codes", () => {
  const d = tmp();
  assert.equal(cli(["init"], { cwd: d }).status, 0);
  assert.equal(cli(["init"], { cwd: d }).status, 1);
  assert.doesNotThrow(() => loadPolicy(join(d, "agentbreaker.json")));
  mkdirSync(join(d, ".agentbreaker"));
  assert.equal(cli(["verify-log"], { cwd: d }).status, 1);                    // missing
  writeFileSync(join(d, ".agentbreaker/audit.jsonl"), "");
  assert.equal(cli(["verify-log"], { cwd: d }).status, 1);                    // empty = nothing proven
  const a = new AuditLog(join(d, "l.jsonl")); a.write("x"); a.write("y"); const head = a.head; a.close();
  assert.equal(cli(["verify-log", "l.jsonl"], { cwd: d }).status, 0);
  assert.equal(cli(["verify-log", "l.jsonl", "--head", head], { cwd: d }).status, 0);
  assert.equal(cli(["verify-log", "--head", "0".repeat(64), "l.jsonl"], { cwd: d }).status, 1);
  writeFileSync(join(d, "n.jsonl"), "null\n");
  const r = cli(["verify-log", "n.jsonl"], { cwd: d }); assert.equal(r.status, 1); assert.match(r.stdout, /TAMPERED/);
  rmSync(d, { recursive: true });
});

test("cli: non-interactive run (stdin not a TTY) falls back to kill, exits 137, and the log verifies", () => {
  const d = tmp();
  const r = cli(["run", "--", NODE, "-e", `require('fs').writeFileSync('.env','x');setInterval(()=>{},1000)`], { cwd: d });
  assert.equal(r.status, 137, r.stderr);
  assert.match(r.stderr, /TRIPPED: protected path modified: \.env/);
  assert.match(r.stderr, /on_trip=kill/);
  assert.equal(cli(["verify-log"], { cwd: d }).status, 0);
  rmSync(d, { recursive: true });
});

test("cli: a policy with spend limits but no prices warns up front, not only at exit", () => {
  const d = tmp();
  cli(["init"], { cwd: d });
  const r = cli(["run", "--policy", "agentbreaker.json", "--", NODE, "-e", "0"], { cwd: d });
  assert.equal(r.status, 0);
  assert.match(r.stderr, /prices.*empty|spend will NOT be counted/i);
  assert.match(r.stderr, /audit head [0-9a-f]{64}/);
  rmSync(d, { recursive: true });
});
