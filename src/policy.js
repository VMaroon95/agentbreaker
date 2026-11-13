import { readFileSync } from "node:fs";

export const DEFAULT_POLICY = {
  workspace: ".",
  on_trip: "pause",            // pause: freeze the agent and wait for a decision. kill: stop it immediately.
  pause_timeout_s: 600,        // no decision in this time -> kill
  notify_command: null,        // e.g. ["./notify.sh"]; message arrives in $AGENTBREAKER_MESSAGE and as last argument
  limits: {
    max_usd: null,
    max_usd_per_hour: null,
    max_tokens: null,
    max_requests_per_minute: 120,
    max_deletes_per_minute: 50,
    max_writes_per_minute: 600,
    max_upload_mb: 50,
    max_blocked_attempts: 5,
    max_runtime_minutes: null,
  },
  egress: { mode: "enforce", allow: [] },   // mode: enforce | log. Model API hosts are always allowed.
  protected_paths: [".env", ".env.*", ".git/config", ".git/hooks/**", ".ssh/**", ".npmrc", ".claude/settings*.json", ".mcp.json"],
  ignore: [".git/objects", "node_modules", ".agentbreaker"],
  upstreams: { anthropic: "https://api.anthropic.com", openai: "https://api.openai.com" },
  prices: [],                  // [{ "match": "model-name-prefix", "input_per_mtok": 0, "output_per_mtok": 0 }]  (USD per million tokens)
};

const LIMIT_KEYS = Object.keys(DEFAULT_POLICY.limits);
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

export function normalizePolicy(user = {}) {
  if (!isObj(user)) throw new Error("policy must be a JSON object");
  const known = new Set(Object.keys(DEFAULT_POLICY));
  for (const k of Object.keys(user)) if (!known.has(k)) throw new Error(`unknown policy key: ${k}`);
  const p = structuredClone(DEFAULT_POLICY);
  for (const k of Object.keys(user)) {
    if (k === "limits") {
      if (!isObj(user.limits)) throw new Error("limits must be an object");
      for (const lk of Object.keys(user.limits)) {
        if (!LIMIT_KEYS.includes(lk)) throw new Error(`unknown limit: ${lk}`);
        const v = user.limits[lk];
        if (v !== null && !(typeof v === "number" && Number.isFinite(v) && v > 0)) throw new Error(`limit ${lk} must be a positive number or null`);
        p.limits[lk] = v;
      }
    } else if (k === "egress") {
      if (!isObj(user.egress)) throw new Error("egress must be an object");
      p.egress = { ...p.egress, ...user.egress };
    } else if (k === "upstreams") {
      p.upstreams = { ...p.upstreams, ...user.upstreams };
    } else p[k] = user[k];
  }
  if (!["pause", "kill"].includes(p.on_trip)) throw new Error("on_trip must be pause or kill");
  if (!["enforce", "log"].includes(p.egress.mode)) throw new Error("egress.mode must be enforce or log");
  if (!(p.pause_timeout_s > 0)) throw new Error("pause_timeout_s must be positive");
  for (const key of ["protected_paths", "ignore"]) if (!Array.isArray(p[key]) || p[key].some((x) => typeof x !== "string")) throw new Error(`${key} must be a list of strings`);
  if (!Array.isArray(p.egress.allow) || p.egress.allow.some((x) => typeof x !== "string")) throw new Error("egress.allow must be a list of strings");
  if (p.notify_command !== null && (!Array.isArray(p.notify_command) || !p.notify_command.length || p.notify_command.some((x) => typeof x !== "string"))) throw new Error("notify_command must be a non-empty array of strings (no shell)");
  if (!Array.isArray(p.prices) || p.prices.some((x) => !x || typeof x.match !== "string" || !(x.input_per_mtok >= 0) || !(x.output_per_mtok >= 0))) throw new Error("prices entries need match, input_per_mtok, output_per_mtok");
  return p;
}

export function loadPolicy(file) {
  return normalizePolicy(file ? JSON.parse(readFileSync(file, "utf8")) : {});
}

// Glob -> RegExp. `*` = within one path segment, `**` = across segments, `?` = one char. Everything else is literal.
export function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") { re += ".*"; i++; if (glob[i + 1] === "/") i++; }
      else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^(?:.*/)?${re}$`);
}

export function hostMatches(host, patterns) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return patterns.some((p) => {
    const pat = p.toLowerCase();
    return pat.startsWith("*.") ? h.endsWith(pat.slice(1)) && h.length > pat.length - 1 : h === pat;
  });
}
