import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { resolve } from "node:path";
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
  const child = spawn(argv[0], argv.slice(1), { cwd: root, env, stdio: "inherit", detached: true });
  log("start", { argv, pid: child.pid, port, policy_workspace: root });
  const fsm = new FsMonitor({ root, breaker, audit: log, intervalMs: pollMs });
  fsm.start();
  const clock = setInterval(() => breaker.tick(), 1000); clock.unref?.();

  let exited = null, handling = false;
  const done = new Promise((r) => {
    child.on("exit", (code, sig) => { exited = { code, sig }; r(); });
    child.on("error", (e) => { if (child.pid === undefined) { exited = { code: 127, sig: null, error: e.message }; r(); } });
  });

  breaker.on("trip", async (trip) => {
    if (handling || exited) return;
    handling = true;
    log("trip", trip);
    out(`\n[agentbreaker] TRIPPED: ${trip.reason} (limit ${trip.limit}, value ${trip.value})\n`);
    notify(policy, `agentbreaker tripped: ${trip.reason}`);
    if (policy.on_trip === "kill") { log("kill", {}); out("[agentbreaker] agent killed (on_trip=kill)\n"); killGroup(child, "SIGKILL"); return; }
    killGroup(child, "SIGSTOP");
    log("paused", {});
    let decision = "kill";
    try {
      decision = await Promise.race([ask(trip), new Promise((r) => setTimeout(() => r("kill"), policy.pause_timeout_s * 1000).unref?.())]);
    } catch { /* default kill */ }
    if (exited) return;
    if (decision === "resume") {
      breaker.resume(); log("resume", {}); out("[agentbreaker] resumed\n");
      killGroup(child, "SIGCONT");
    } else {
      log("kill", {}); out("[agentbreaker] agent killed\n"); killGroup(child, "SIGCONT"); killGroup(child, "SIGKILL");
    }
    handling = false;
  });

  const relay = (s) => () => killGroup(child, s);
  for (const s of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(s, relay(s));

  await done;
  fsm.poll(); fsm.stop(); clearInterval(clock);
  log("exit", { ...exited, stats: breaker.stats() });
  proxy.closeAllConnections?.(); proxy.close(); audit.close();
  out(`[agentbreaker] done. ${JSON.stringify(breaker.stats())}\n`);
  if (breaker.stats().unpriced_models.length) out(`[agentbreaker] warning: no price for ${breaker.stats().unpriced_models.join(", ")}; spend limits did not count these. Add entries to "prices".\n`);
  return exited.sig ? 128 + (({ SIGKILL: 9, SIGINT: 2, SIGTERM: 15 })[exited.sig] ?? 1) : exited.code ?? 1;
}

function notify(policy, msg) {
  if (!policy.notify_command) return;
  try {
    const [cmd, ...args] = policy.notify_command;
    spawn(cmd, [...args, msg], { stdio: "ignore", detached: true, env: { ...process.env, AGENTBREAKER_MESSAGE: msg } }).unref();
  } catch { /* notification is best-effort */ }
}

export function terminalAsk(trip) {
  return new Promise((resolveAsk) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    rl.question("[agentbreaker] agent is frozen. Resume (r) or kill (k)? ", (a) => { rl.close(); resolveAsk(/^r/i.test(a.trim()) ? "resume" : "kill"); });
    rl.on("close", () => resolveAsk("kill"));
  });
}
