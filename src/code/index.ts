import type { Finding } from "../scan/findings.js";
import { checkAuthConfig, configFor, readSupabaseConfigs } from "./config.js";
import { FILE_CHECKS } from "./rules.js";
import { checkSecrets } from "./secrets.js";
import { checkServerFile } from "./server.js";
import { collectFiles } from "./source.js";

export interface CodeReport {
  /** How many source, config and .env files were read. */
  files: number;
  findings: Finding[];
}

/**
 * Static checks on the app's own source code: XSS, leaked secrets, server
 * functions anyone can call or call without limit, unverified webhooks,
 * SSRF, SQL and command injection, open redirects and risky auth settings.
 * Nothing is executed and nothing leaves your machine.
 */
export function runCodeChecks(projectDir: string): CodeReport {
  const files = collectFiles(projectDir);
  const configs = readSupabaseConfigs(files);
  const findings: Finding[] = [...checkSecrets(files, projectDir), ...configs.flatMap(checkAuthConfig)];
  for (const file of files.filter((f) => f.kind !== "test")) {
    for (const check of FILE_CHECKS) findings.push(...check(file));
    findings.push(...checkServerFile(file, configFor(configs, file)));
  }
  return { files: files.length, findings: dedupe(findings) };
}

/** One finding per rule and line. */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.targetKey)) return false;
    seen.add(f.targetKey);
    return true;
  });
}
