import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { OWASP, type Finding, type Severity } from "../scan/findings.js";
import { codeFinding, matches } from "./finding.js";
import { SECRET_PATTERNS, withArticle } from "./patterns.js";
import type { SourceFile } from "./source.js";

const LOWER: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "low", info: "info" };

export function checkSecrets(files: SourceFile[], projectDir: string): Finding[] {
  const findings: Finding[] = [];
  const ignored = gitignoredEnv(projectDir);

  for (const file of files) {
    if (file.kind === "env") {
      findings.push(...checkEnvFile(file, ignored(file.path)));
      continue;
    }
    for (const secret of SECRET_PATTERNS) {
      for (const m of matches(file.text, secret.pattern)) {
        if (secret.confirm && !secret.confirm(m[0])) continue;
        const inBrowser = file.kind === "client";
        const finding = codeFinding(file, m.index, {
          rule: "secret-in-code",
          severity: inBrowser ? secret.severity : LOWER[secret.severity],
          title: inBrowser
            ? `${capitalize(withArticle(secret.name))} is in code that ships to the browser.`
            : `${capitalize(withArticle(secret.name))} is written into the code.`,
          detail: [
            inBrowser
              ? "Anyone can open your website's JavaScript and copy it."
              : "Anyone who can see this repository can copy it.",
            secret.note,
          ]
            .filter(Boolean)
            .join(" "),
          fix: inBrowser
            ? "Rotate the key now, then move the code that uses it into an edge function and read the key from an environment variable."
            : "Rotate the key, then read it from an environment variable instead (Deno.env.get / process.env).",
          owasp: OWASP.authentication,
        });
        if (finding) findings.push(finding);
      }
    }
  }

  findings.push(...checkClientEnvVars(files));
  return findings;
}

/** Names that sound like secrets, unless they also say they're public. */
const SECRET_NAME = /(SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|API_KEY|APIKEY|ACCESS_KEY|TOKEN|PASSWORD|WEBHOOK)/;
const PUBLIC_NAME = /(PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|URL|PROJECT_ID|MEASUREMENT|CLIENT_ID|RECAPTCHA|MAPS)/;
const CLIENT_PREFIX = /^(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)/;

function looksSecret(name: string): boolean {
  const rest = name.replace(CLIENT_PREFIX, "");
  return SECRET_NAME.test(rest) && !PUBLIC_NAME.test(rest);
}

/**
 * VITE_*, NEXT_PUBLIC_* and similar variables are pasted into the website's
 * JavaScript at build time. A secret in one of them is public.
 */
function checkClientEnvVars(files: SourceFile[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  // Client variables in .env files: a value that is a secret key whatever the
  // name says (VITE_SUPABASE_KEY=<service_role>), or a secret-sounding name.
  for (const file of files.filter((f) => f.kind === "env" && !isExampleEnv(f.path))) {
    for (const m of matches(file.text, /^\s*((?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)\w+)\s*=\s*(\S.*)$/gm)) {
      const [name, value] = [m[1]!, m[2]!.replace(/^["']|["']$/g, "")];
      if (seen.has(name)) continue;
      const leaked = SECRET_PATTERNS.find(
        (s) => s.severity !== "medium" && [...matches(value, s.pattern)].some((v) => !s.confirm || s.confirm(v[0])),
      );
      if (leaked) {
        seen.add(name);
        const finding = codeFinding(file, m.index, {
          rule: "secret-in-client-env",
          severity: "critical",
          title: `${name} holds ${withArticle(leaked.name)}, and ${name.match(CLIENT_PREFIX)![1]} variables are built into your website.`,
          detail: ["Anyone can read it in the browser.", leaked.note].filter(Boolean).join(" "),
          fix: "Rotate the key now. The browser should only ever get the publishable (anon) key.",
          owasp: OWASP.authentication,
        });
        if (finding) findings.push(finding);
      } else if (looksSecret(name) && !isPlaceholder(value)) {
        seen.add(name);
        const finding = codeFinding(file, m.index, clientEnvIssue(name));
        if (finding) findings.push(finding);
      }
    }
  }

  // Secret-sounding client variables the code reads, when no .env file showed them.
  const usage = /import\.meta\.env\.((?:VITE_|PUBLIC_)\w+)|process\.env\.((?:NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)\w+)/g;
  for (const file of files.filter((f) => f.kind === "client")) {
    for (const m of matches(file.code, usage)) {
      const name = (m[1] ?? m[2])!;
      if (!looksSecret(name) || seen.has(name)) continue;
      seen.add(name);
      const finding = codeFinding(file, m.index, clientEnvIssue(name));
      if (finding) findings.push(finding);
    }
  }
  return findings;
}

function clientEnvIssue(name: string) {
  return {
    rule: "secret-in-client-env",
    severity: "high" as const,
    title: `${name} sounds like a secret, but variables starting with ${name.match(CLIENT_PREFIX)![1]} are built into your website.`,
    detail: "Anyone can open the browser's dev tools and read it. Ignore this if the value is meant to be public.",
    fix: "Rotate the key, remove the prefix, and call the service from an edge function that reads the key with Deno.env.get().",
    owasp: OWASP.authentication,
  };
}

/** A .env file with real secrets that git would commit. */
function checkEnvFile(file: SourceFile, gitignored: boolean): Finding[] {
  if (gitignored || isExampleEnv(file.path)) return [];
  const secrets = [...matches(file.text, /^\s*([A-Z0-9_]+)\s*=\s*(\S.*)$/gm)].filter(
    (m) => !CLIENT_PREFIX.test(m[1]!) && looksSecret(m[1]!) && !isPlaceholder(m[2]!),
  );
  if (secrets.length === 0) return [];
  const finding = codeFinding(file, secrets[0]!.index, {
    rule: "env-file-not-ignored",
    severity: "medium",
    title: `${file.path} holds secrets (${secrets.map((m) => m[1]).join(", ")}) and isn't in .gitignore.`,
    detail: "One `git add .` and the keys are in your repository for good.",
    fix: `Add ${file.path} to .gitignore. If it was ever pushed, rotate the keys.`,
    owasp: OWASP.authentication,
  });
  return finding ? [finding] : [];
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function isExampleEnv(path: string): boolean {
  return /\.(example|sample|template|dist)$/.test(path);
}

function isPlaceholder(value: string): boolean {
  const v = value.trim().replace(/^["']|["']$/g, "");
  return v === "" || /^(your|<|\$\{|xxx|changeme|replace|todo|example|placeholder|\*+$)/i.test(v);
}

/**
 * Returns a check for whether a .env path is ignored by git: by the
 * project's .gitignore or one in a folder above the file, as git applies them.
 */
function gitignoredEnv(projectDir: string): (path: string) => boolean {
  const cache = new Map<string, string[]>();
  const patternsIn = (dir: string): string[] => {
    if (!cache.has(dir)) {
      const file = join(projectDir, dir, ".gitignore");
      cache.set(
        dir,
        existsSync(file)
          ? readFileSync(file, "utf8")
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l && !l.startsWith("#") && !l.startsWith("!"))
          : [],
      );
    }
    return cache.get(dir)!;
  };

  return (path) => {
    const parts = path.split("/");
    const name = parts.pop()!;
    // The project root, then each folder down to the file's own.
    for (let depth = 0; depth <= parts.length; depth++) {
      const dir = parts.slice(0, depth).join("/");
      const relative = parts.slice(depth).concat(name).join("/");
      if (patternsIn(dir).some((p) => matchesGitignore(p, name, relative))) return true;
    }
    return false;
  };
}

/**
 * Git's rules, simplified: a pattern with a slash at the start or in the
 * middle is relative to its .gitignore's folder; one without matches the
 * file name in any folder below it.
 */
function matchesGitignore(line: string, name: string, path: string): boolean {
  const anchored = line.replace(/\/$/, "").includes("/");
  const pattern = line.replace(/^\//, "").replace(/\/$/, "");
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^${escaped.replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\u0000/g, "(?:.*/)?")}$`);
  return anchored ? re.test(path) : re.test(name) || re.test(path);
}
