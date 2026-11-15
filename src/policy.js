import { readFileSync } from "node:fs";
import { domainToASCII } from "node:url";

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
const validPrice = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0;
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
      for (const ek of Object.keys(user.egress)) if (!["mode", "allow"].includes(ek)) throw new Error(`unknown egress key: ${ek}`);
      p.egress = { ...p.egress, ...user.egress };
    } else if (k === "upstreams") {
      if (!isObj(user.upstreams)) throw new Error("upstreams must be an object");
      for (const [name, url] of Object.entries(user.upstreams)) {
        if (!/^[a-z0-9_-]+$/i.test(name)) throw new Error(`bad upstream name: ${name}`);
        let u; try { u = new URL(url); } catch { throw new Error(`upstream ${name} must be an http(s) URL`); }
        if (typeof url !== "string" || !["http:", "https:"].includes(u.protocol)) throw new Error(`upstream ${name} must be an http(s) URL`);
        p.upstreams[name] = url;
      }
    } else p[k] = user[k];
  }
  if (!["pause", "kill"].includes(p.on_trip)) throw new Error("on_trip must be pause or kill");
  if (!["enforce", "log"].includes(p.egress.mode)) throw new Error("egress.mode must be enforce or log");
  if (typeof p.workspace !== "string" || !p.workspace) throw new Error("workspace must be a non-empty string");
  if (!(typeof p.pause_timeout_s === "number" && p.pause_timeout_s > 0 && p.pause_timeout_s <= 2_000_000)) throw new Error("pause_timeout_s must be a positive number (at most 2000000)");
  for (const key of ["protected_paths", "ignore"]) if (!Array.isArray(p[key]) || p[key].some((x) => typeof x !== "string")) throw new Error(`${key} must be a list of strings`);
  if (!Array.isArray(p.egress.allow) || p.egress.allow.some((x) => typeof x !== "string")) throw new Error("egress.allow must be a list of strings");
  if (p.notify_command !== null && (!Array.isArray(p.notify_command) || !p.notify_command.length || p.notify_command.some((x) => typeof x !== "string"))) throw new Error("notify_command must be a non-empty array of strings (no shell)");
  if (!Array.isArray(p.prices) || p.prices.some((x) => !x || typeof x.match !== "string" || !validPrice(x.input_per_mtok) || !validPrice(x.output_per_mtok))) throw new Error("prices entries need match, input_per_mtok, output_per_mtok");
  return p;
}

export function loadPolicy(file) {
  return normalizePolicy(file ? JSON.parse(readFileSync(file, "utf8")) : {});
}

// Glob -> RegExp. `*` = within one path segment, `**` = across segments, `?` = one char. Everything else is literal.
// Matches at any depth (implicit leading "**/"). The "s" flag matters: file names may contain newlines.
export function globToRegExp(glob, { caseInsensitive = false } = {}) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        while (glob[i + 1] === "*") i++;
        if (glob[i + 1] === "/") { i++; re += "(?:[^/]*/)*"; } // "**/" = zero or more directories
        else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  // Adjacent identical wildcards are redundant; collapsing them keeps matching linear (a chain of "**/" was O(n^k)).
  re = re.replace(/(?:\(\?:\[\^\/\]\*\/\)\*){2,}/g, "(?:[^/]*/)*").replace(/(?:\.\*){2,}/g, ".*");
  return new RegExp(`^(?:.*/)?${re}$`, caseInsensitive ? "si" : "s");
}

// Lowercase, strip one trailing dot, convert IDN to punycode. Returns "" if the name is not a plausible host.
export function normalizeHost(host) {
  let h = String(host).trim().toLowerCase().replace(/\.$/, "");
  if (/^\[.*\]$/.test(h)) h = h.slice(1, -1);
  if (h.includes(":")) return /^[0-9a-f:.]+$/.test(h) ? h : "";   // IPv6 literal
  if (/[\/?#@\\\s%]/.test(h)) return "";   // domainToASCII() silently truncates at these ("evil.com/x" -> "evil.com")
  const a = domainToASCII(h);
  return /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/.test(a) ? a : "";
}

export function hostMatches(host, patterns) {
  const h = normalizeHost(host);
  if (!h) return false;
  return patterns.some((p) => {
    const wild = p.startsWith("*.");
    const pat = normalizeHost(wild ? p.slice(2) : p);
    if (!pat) return false;
    return wild ? h.endsWith("." + pat) : h === pat;
  });
}
