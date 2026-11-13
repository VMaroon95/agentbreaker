import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { loadPolicy, DEFAULT_POLICY } from "./policy.js";
import { run, terminalAsk } from "./run.js";
import { verifyChain } from "./audit.js";

const HELP = `agentbreaker - a circuit breaker for autonomous AI agents

  agentbreaker run [--policy FILE] [--on-trip pause|kill] -- <command> [args...]
  agentbreaker init [FILE]            write an example policy (default agentbreaker.json)
  agentbreaker verify-log [FILE]      check the audit log hash chain (default .agentbreaker/audit.jsonl)

Exit codes: the agent's own code on run; 0 ok / 1 problem for other commands; 2 usage error.`;

export async function main(args) {
  const [cmd, ...rest] = args;
  try {
    if (!cmd || cmd === "-h" || cmd === "--help") { console.log(HELP); return cmd ? 0 : 2; }
    if (cmd === "init") {
      const f = rest[0] ?? "agentbreaker.json";
      if (existsSync(f)) { console.error(`${f} already exists`); return 1; }
      writeFileSync(f, JSON.stringify({ ...DEFAULT_POLICY, limits: { ...DEFAULT_POLICY.limits, max_usd: 5, max_usd_per_hour: 2 }, egress: { mode: "enforce", allow: ["github.com", "*.githubusercontent.com", "registry.npmjs.org"] } }, null, 2) + "\n");
      console.log(`wrote ${f}. Add "prices" for your models so spend limits work.`);
      return 0;
    }
    if (cmd === "verify-log") {
      const r = verifyChain(readFileSync(rest[0] ?? ".agentbreaker/audit.jsonl", "utf8"));
      console.log(r.ok ? `OK (${r.lines} entries)` : `TAMPERED or corrupt at line ${r.line}`);
      return r.ok ? 0 : 1;
    }
    if (cmd === "run") {
      const i = rest.indexOf("--");
      if (i < 0 || i === rest.length - 1) { console.error("usage: agentbreaker run [options] -- <command>"); return 2; }
      const opts = rest.slice(0, i), argv = rest.slice(i + 1);
      let file = null, onTrip = null;
      for (let j = 0; j < opts.length; j++) {
        if (opts[j] === "--policy") file = opts[++j];
        else if (opts[j] === "--on-trip") onTrip = opts[++j];
        else { console.error(`unknown option ${opts[j]}`); return 2; }
      }
      const policy = loadPolicy(file);
      if (onTrip) { if (!["pause", "kill"].includes(onTrip)) { console.error("--on-trip must be pause or kill"); return 2; } policy.on_trip = onTrip; }
      if (!process.stdin.isTTY && policy.on_trip === "pause") policy.on_trip = "kill"; // nobody to answer
      return await run({ policy, argv, ask: terminalAsk });
    }
    console.error(`unknown command ${cmd}\n${HELP}`); return 2;
  } catch (e) { console.error(`agentbreaker: ${e.message}`); return 2; }
}
