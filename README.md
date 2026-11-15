# AgentBreaker

A local circuit breaker for autonomous AI agents. Wrap any agent command; when it overspends, loops, mass-deletes files, touches secrets, or phones an unknown host, AgentBreaker **freezes it** (SIGSTOP) and asks you: resume or kill.

## Install

Not on the npm registry yet. Install from GitHub: `npm install -g github:VMaroon95/agentbreaker`

```
agentbreaker init                      # writes agentbreaker.json
agentbreaker run --policy agentbreaker.json -- claude
agentbreaker verify-log                # checks the tamper-evident audit log
```

Zero dependencies. Node 20+. macOS/Linux. MIT.

Example: an agent writes `.env`, the default policy trips and (non-interactive) kills it.

```
[agentbreaker] TRIPPED: protected path modified: .env (limit .env, value .env)
[agentbreaker] agent killed (on_trip=kill)
```

In a terminal the agent is frozen instead and you are asked to resume or kill.

## What it watches

| Guard | How |
|---|---|
| Spend / tokens (total, per hour) | Local reverse proxy. Child gets `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing at it; usage is read from JSON and SSE responses. You supply `prices` (USD per million tokens). Prices match by longest case-insensitive model prefix. Models with no price are listed in the stats and a warning is printed at startup if a spend limit is set but `prices` is empty. gzip/deflate/br responses are decompressed for accounting. |
| Request loops | Requests per minute, counting only API requests through the reverse proxy (not forward-proxy or CONNECT traffic) |
| Network egress | `HTTP_PROXY`/`HTTPS_PROXY` allowlist (CONNECT + plain HTTP). Repeated blocked attempts trip the breaker. Upload volume cap. |
| File changes | Polling snapshot of the workspace: writes/deletes per minute, plus protected paths (`.env`, `.ssh/**`, `.git/hooks/**`, `.mcp.json`, ...) trip on first touch |
| Runtime | Max minutes |

On trip: `pause` (default; agent frozen, you decide, no answer in `pause_timeout_s` means kill) or `kill` (whole process group). Non-interactive runs fall back to `kill`. Every event goes to `.agentbreaker/audit.jsonl`, a hash chain, so accidental or naive edits, deletions, reordering and mid-file removals are detectable (`agentbreaker verify-log`). Runs append to the same chain; the head hash is printed at the end of each run.

## Limits (read these)

- **Cooperative, not a sandbox.** An agent that ignores proxy env vars, or opens raw sockets, bypasses the egress guard and the token counter. Run it in a container with no direct network route for real enforcement.
- **File monitoring is after-the-fact** (polled every 500 ms): it detects and freezes, it cannot prevent a write.
- HTTPS tunnels are only visible by hostname and byte count, not content.
- **The audit chain is unkeyed, not tamper-proof.** Anyone who can write the file can recompute a valid chain, wipe it, or truncate the tail, and truncation of the last N lines is undetectable from the log alone. Store the printed head hash somewhere the agent cannot write and check with `verify-log --head HASH`; that does detect tail truncation. An empty log is reported as a failure.
- CONNECT tunnels to model hosts (e.g. api.anthropic.com) are always allowed and their tokens are not counted; only traffic through the reverse-proxy base URLs is metered.
- File monitor: symlinked directories are not followed; directory creation/deletion is not tracked; a file created and removed within one 500 ms poll is missed; above 200,000 entries the snapshot is truncated (files past the cap are invisible, an `fs_truncated` event is audited and deletions are not reported). A user-supplied `ignore` list replaces the default ignores.
- Process control: processes that leave the agent's process group (`setsid`) escape the kill, and background processes that outlive the leader are not killed. If agentbreaker itself is SIGKILLed the detached agent keeps running. Interactive full-screen TUI agents under a detached process group are untested.
- Not tested on Windows.

## Test

`npm test` (sets `NO_PROXY` for localhost; needed if your shell has `NODE_USE_ENV_PROXY=1`). 91 tests (26 core in `test/agentbreaker.test.js`, 65 adversarial regression tests in `test/hard.test.js`) including real child processes, SIGSTOP freeze, grandchild kill, a real proxy, SSE split at every byte, and audit tamper cases.
