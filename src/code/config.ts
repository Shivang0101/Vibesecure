import { OWASP, type Finding } from "../scan/findings.js";
import { codeFinding, type CodeIssue } from "./finding.js";
import type { SourceFile } from "./source.js";

interface ConfigValue {
  value: string;
  /** Position of the line in the file, for reporting. */
  index: number;
}

/** supabase/config.toml, read as sections of key = value lines. */
export interface SupabaseConfig {
  file: SourceFile;
  /** Folder that holds the supabase/ folder, e.g. "" or "apps/web/". */
  prefix: string;
  get(section: string, key: string): ConfigValue | undefined;
}

/** Every supabase/config.toml in the project, most deeply nested first. */
export function readSupabaseConfigs(files: SourceFile[]): SupabaseConfig[] {
  return files
    .filter((f) => /(^|\/)supabase\/config\.toml$/.test(f.path))
    .map(readSupabaseConfig)
    .sort((a, b) => b.prefix.length - a.prefix.length);
}

/** The config.toml that belongs to a file: the one in the nearest enclosing project. */
export function configFor(configs: SupabaseConfig[], file: SourceFile): SupabaseConfig | null {
  return configs.find((c) => file.path.startsWith(c.prefix)) ?? null;
}

function readSupabaseConfig(file: SourceFile): SupabaseConfig {

  const sections = new Map<string, Map<string, ConfigValue>>();
  let current = "";
  let index = 0;
  for (const rawLine of file.text.split("\n")) {
    const line = stripComment(rawLine).trim();
    const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (header) {
      current = header[1]!.replace(/"/g, "");
    } else {
      const pair = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
      if (pair) {
        const values = sections.get(current) ?? new Map<string, ConfigValue>();
        values.set(pair[1]!, { value: pair[2]!.trim().replace(/^"|"$/g, ""), index });
        sections.set(current, values);
      }
    }
    index += rawLine.length + 1;
  }
  const prefix = file.path.slice(0, file.path.length - "supabase/config.toml".length);
  return { file, prefix, get: (section, key) => sections.get(section)?.get(key) };
}

function stripComment(line: string): string {
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') inString = !inString;
    if (line[i] === "#" && !inString) return line.slice(0, i);
  }
  return line;
}

/** True when supabase/config.toml switches off JWT checks for an edge function. */
export function verifyJwtOff(config: SupabaseConfig | null, functionName: string | undefined): boolean {
  if (!config || !functionName) return false;
  return config.get(`functions.${functionName}`, "verify_jwt")?.value === "false";
}

/** Auth settings in config.toml that make accounts easier to abuse. */
export function checkAuthConfig(config: SupabaseConfig | null): Finding[] {
  if (!config) return [];
  const out: Finding[] = [];
  const add = (value: ConfigValue, issue: CodeIssue) => {
    const finding = codeFinding(config.file, value.index, issue);
    if (finding) out.push(finding);
  };
  const note = "This is the setting in supabase/config.toml; check the same setting in the dashboard for your live project.";

  const confirmations = config.get("auth.email", "enable_confirmations");
  if (confirmations?.value === "false") {
    add(confirmations, {
      rule: "auth-email-unconfirmed",
      severity: "low",
      title: "Email confirmation is off: people can sign up with an email address they don't own.",
      detail:
        "That's the default for local development. Make sure it's on for your live project " +
        "(Authentication → Sign In / Providers → Email), or someone can register with your customer's address.",
      fix: "Set enable_confirmations = true under [auth.email], or check the dashboard setting.",
      owasp: OWASP.authentication,
    });
  }

  const anonymous = config.get("auth", "enable_anonymous_sign_ins");
  if (anonymous?.value === "true") {
    add(anonymous, {
      rule: "auth-anonymous-sign-ins",
      severity: "medium",
      title: "Anonymous sign-ins are on, so policies written for signed-in users also let in guests.",
      detail: "Anonymous users get the authenticated role. Any policy that says `to authenticated` treats them like real accounts.",
      fix: "Turn it off, or add `and (auth.jwt()->>'is_anonymous')::boolean is not true` to policies meant for real accounts.",
      owasp: OWASP.authentication,
    });
  }

  const passwordLength = config.get("auth", "minimum_password_length");
  if (passwordLength && Number(passwordLength.value) < 8) {
    add(passwordLength, {
      rule: "auth-weak-passwords",
      severity: "low",
      title: `Passwords can be as short as ${passwordLength.value} characters.`,
      detail: `8 or more is the usual minimum. ${note}`,
      fix: "Set minimum_password_length to at least 8 (12 is better) under [auth].",
      owasp: OWASP.authentication,
    });
  }

  const signIns = config.get("auth.rate_limit", "sign_in_sign_ups");
  if (signIns && Number(signIns.value) > 300) {
    add(signIns, {
      rule: "auth-rate-limit-raised",
      severity: "low",
      title: `Sign-in attempts are allowed at a high rate (${signIns.value} per 5 minutes per IP).`,
      detail: "That makes guessing passwords easier. Supabase's default is 30.",
      fix: "Lower sign_in_sign_ups under [auth.rate_limit] back toward the default.",
      owasp: OWASP.authentication,
    });
  }
  return out;
}
