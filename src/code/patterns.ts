import type { Severity } from "../scan/findings.js";

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  /** How bad it is in browser code. Elsewhere it drops one level, since it's "only" in the repo. */
  severity: Severity;
  /** Extra check on the match, e.g. decoding a JWT. */
  confirm?: (match: string) => boolean;
  note?: string;
}

/**
 * Key formats of services vibe-coded apps commonly use. These are matched on
 * the raw text, comments included: a key in a comment is still leaked.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "Supabase service_role key",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: "critical",
    confirm: (token) => jwtRole(token) === "service_role",
    note: "It bypasses every RLS policy: whoever has it can read and change your whole database.",
  },
  { name: "Supabase secret key", pattern: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, severity: "critical", note: "It bypasses every RLS policy." },
  { name: "Stripe live secret key", pattern: /\b[sr]k_live_[0-9A-Za-z]{16,}/g, severity: "critical", note: "It can move real money." },
  { name: "Stripe test secret key", pattern: /\bsk_test_[0-9A-Za-z]{16,}/g, severity: "medium" },
  { name: "Stripe webhook secret", pattern: /\bwhsec_[0-9A-Za-z]{20,}/g, severity: "high", note: "With it, anyone can fake payment events." },
  { name: "Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, severity: "critical" },
  { name: "OpenAI API key", pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g, severity: "critical" },
  { name: "ElevenLabs API key", pattern: /\bsk_[a-f0-9]{48}\b/g, severity: "critical" },
  { name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical" },
  { name: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})/g, severity: "critical" },
  { name: "Slack token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, severity: "high" },
  { name: "SendGrid API key", pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{30,}/g, severity: "high" },
  { name: "private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, severity: "critical" },
  {
    name: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "medium",
    note: "Some Google keys are meant to be public (Maps, Firebase), but a Gemini key here lets anyone spend your credits. Restrict it to your domain and APIs.",
  },
];

/** Decodes the middle part of a JWT and returns its `role` claim. */
export function jwtRole(token: string): string | undefined {
  try {
    const payload = token.split(".")[1]!;
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return (JSON.parse(json) as { role?: string }).role;
  } catch {
    return undefined;
  }
}

/**
 * Hides anything that looks like a key, so reports and CI logs never repeat
 * a secret: "sk_live_abc...xyz" becomes "sk_live_ab…".
 */
export function maskSecrets(text: string): string {
  let masked = text;
  for (const { pattern } of SECRET_PATTERNS) {
    masked = masked.replace(new RegExp(pattern.source, "g"), (m) => (m.startsWith("-----") ? m : `${m.slice(0, 10)}…`));
  }
  return masked;
}

/** "a Stripe key", "an OpenAI key". */
export function withArticle(name: string): string {
  return `${/^[aeiou]/i.test(name) ? "an" : "a"} ${name}`;
}
