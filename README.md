# AgentBreaker

A local circuit breaker for autonomous AI agents. Wrap any agent command; when it overspends, loops, mass-deletes files, touches secrets, or phones an unknown host, AgentBreaker **freezes it** (SIGSTOP) and asks you: resume or kill.

```
agentbreaker init                      # writes agentbreaker.json
agentbreaker run --policy agentbreaker.json -- claude
agentbreaker verify-log                # checks the tamper-evident audit log
```

Zero dependencies. Node 20+. macOS/Linux. MIT.

## What it watches

| Guard | How |
|---|---|
| Spend / tokens (total, per hour) | Local reverse proxy. Child gets `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing at it; usage is read from JSON and SSE responses. You supply `prices` (USD per million tokens). Unpriced models are reported, never counted as free. |
| Request loops | Requests per minute through the proxy |
| Network egress | `HTTP_PROXY`/`HTTPS_PROXY` allowlist (CONNECT + plain HTTP). Repeated blocked attempts trip the breaker. Upload volume cap. |
| File changes | Polling snapshot of the workspace: writes/deletes per minute, plus protected paths (`.env`, `.ssh/**`, `.git/hooks/**`, `.mcp.json`, ...) trip on first touch |
| Runtime | Max minutes |

On trip: `pause` (default; agent frozen, you decide, no answer in `pause_timeout_s` means kill) or `kill` (whole process group). Non-interactive runs fall back to `kill`. Every event goes to `.agentbreaker/audit.jsonl`, a hash chain, so edits and deletions are detectable.

## Limits (read these)

- **Cooperative, not a sandbox.** An agent that ignores proxy env vars, or opens raw sockets, bypasses the egress guard and the token counter. Run it in a container with no direct network route for real enforcement.
- **File monitoring is after-the-fact** (polled every 500 ms): it detects and freezes, it cannot prevent a write.
- HTTPS tunnels are only visible by hostname and byte count, not content.
- The audit log detects tampering, but an agent with write access to the workspace could delete the whole file. Point it elsewhere for stronger guarantees.
- Not tested on Windows.

## Test

`npm test` (sets `NO_PROXY` for localhost; needed if your shell has `NODE_USE_ENV_PROXY=1`). 26 tests including real child processes, SIGSTOP freeze, grandchild kill, and a real proxy.
