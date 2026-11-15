import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { resolve } from "node:path";
import { constants as osConstants } from "node:os";
import { Breaker } from "./breaker.js";
import { createProxy } from "./proxy.js";
import { FsMonitor } from "./fswatch.js";
import { AuditLog } from "./audit.js";

const killGroup = (child, sig) => { try { process.kill(-child.pid, sig); } catch { try { child.kill(sig); } catch { /* gone */ } } };

// ask(trip) -> Promise<"resume" | "kill">
export async function run({ policy, argv, ask, out = (s) => process.stderr.write(s), pollMs = 500 }) {
  const root = resolve(policy.workspace);
  const audit = new AuditLog(resolve(root, ".agentbreaker/audit.jsonl"));
  const breaker = new Breaker(policy);
  const log = (event, d) => audit.write(event, d);
  const proxy = createProxy({ policy, breaker, audit: log });
  await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
  const port = proxy.address().port;
  const base = `http://127.0.0.1:${port}`;

  const env = {
    ...process.env,
    ANTHROPIC_BASE_URL: `${base}/anthropic`,
    OPENAI_BASE_URL: `${base}/openai/v1`,
    HTTP_PROXY: base, http_proxy: base, HTTPS_PROXY: base, https_proxy: base,
    NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost",
    AGENTBREAKER: "1",
  };
  if ((policy.limits.max_usd || policy.limits.max_usd_per_hour) && !policy.prices.length) out("[agentbreaker] warning: a spend limit is set but \"prices\" is empty, so spend will NOT be counted (token and request limits still work).\n");
  const child = spawn(argv[0], argv.slice(1), { cwd: root, env, stdio: "inherit", detached: true });
  child.on("error", () => {});   // never leave an 'error' event unhandled
  let fsm;
  try {
    log("start", { argv, pid: child.pid, port, policy_workspace: root });
    fsm = new FsMonitor({ root, breaker, audit: log, intervalMs: pollMs });
  } catch (e) { killGroup(child, "SIGKILL"); proxy.close(); throw e; }
  fsm.start();
  const clock = setInterval(() => breaker.tick(), 1000); clock.unref?.();

  let exited = null, handling = false;
  const done = new Promise((r) => {
    child.on("exit", (code, sig) => { exited = { code, sig }; r(); });
    child.on("error", (e) => { if (child.pid === undefined) { exited = { code: 127, sig: null, error: e.message }; r(); } });
  });

  const killNow = () => { killGroup(child, "SIGCONT"); killGroup(child, "SIGKILL"); };
  // Fail closed: if agentbreaker itself breaks (disk full, bug), the agent must not keep running unsupervised.
  const fatal = (e) => { try { out(`[agentbreaker] internal error, killing agent: ${e?.stack ?? e}\n`); } catch { /* ignore */ } killNow(); try { log("fatal", { message: String(e?.message ?? e) }); } catch { /* ignore */ } };
  process.on("uncaughtException", fatal); process.on("unhandledRejection", fatal);

  breaker.on("trip", async (trip) => {
    if (handling || exited) return;
    handling = true;
    try {
      log("trip", trip);
      out(`\n[agentbreaker] TRIPPED: ${trip.reason} (limit ${trip.limit}, value ${trip.value})\n`);
      notify(policy, `agentbreaker tripped: ${trip.reason}`);
      if (policy.on_trip === "kill") { log("kill", {}); out("[agentbreaker] agent killed (on_trip=kill)\n"); killNow(); return; }
      killGroup(child, "SIGSTOP");
      log("paused", {});
      let decision = "kill", timer;
      try {
        decision = await Promise.race([ask(trip), new Promise((r) => { timer = setTimeout(() => r("kill"), policy.pause_timeout_s * 1000); timer.unref?.(); })]);
      } catch { /* default kill */ } finally { clearTimeout(timer); }
      if (exited) return;
      if (decision === "resume") {
        breaker.resume(); log("resume", {}); out("[agentbreaker] resumed\n");
        killGroup(child, "SIGCONT");
      } else {
        log("kill", {}); out("[agentbreaker] agent killed\n"); killNow();
      }
    } catch (e) { fatal(e); }
    finally { handling = false; }
  });

  // Relay signals to the whole group. A frozen group cannot act on a signal until continued, so also SIGCONT.
  const relays = ["SIGINT", "SIGTERM", "SIGHUP"].map((s) => [s, () => { killGroup(child, s); killGroup(child, "SIGCONT"); }]);
  for (const [s, f] of relays) process.on(s, f);

  await done;
  if (exited?.error) out(`[agentbreaker] cannot start ${argv[0]}: ${exited.error}\n`);
  for (const [s, f] of relays) process.off(s, f);
  process.off("uncaughtException", fatal); process.off("unhandledRejection", fatal);
  fsm.poll(); fsm.stop(); clearInterval(clock);
  log("exit", { ...exited, stats: breaker.stats() });
  proxy.closeAllConnections?.(); proxy.close(); audit.close();
  out(`[agentbreaker] audit head ${audit.head} (${audit.lines} entries this run). Store it elsewhere to detect truncation: agentbreaker verify-log --head <hash>\n`);
  out(`[agentbreaker] done. ${JSON.stringify(breaker.stats())}\n`);
  if (breaker.stats().unpriced_models.length) out(`[agentbreaker] warning: no price for ${breaker.stats().unpriced_models.join(", ")}; spend limits did not count these. Add entries to "prices".\n`);
  return exited.sig ? 128 + (osConstants.signals[exited.sig] ?? 1) : exited.code ?? 1;
}

function notify(policy, msg) {
  if (!policy.notify_command) return;
  try {
    const [cmd, ...args] = policy.notify_command;
    const c = spawn(cmd, [...args, msg], { stdio: "ignore", detached: true, env: { ...process.env, AGENTBREAKER_MESSAGE: msg } });
    c.on("error", () => {});   // a missing notify command must not crash us (unhandled 'error' event)
    c.unref();
  } catch { /* notification is best-effort */ }
}

export function terminalAsk(trip) {
  return new Promise((resolveAsk) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    rl.question("[agentbreaker] agent is frozen. Resume (r) or kill (k)? ", (a) => { rl.close(); resolveAsk(/^r/i.test(a.trim()) ? "resume" : "kill"); });
    rl.on("close", () => resolveAsk("kill"));
  });
}
