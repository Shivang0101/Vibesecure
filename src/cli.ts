#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import * as clack from "@clack/prompts";
import pc from "picocolors";
import { AnthropicModel, DEFAULT_EFFORT, DEFAULT_MODEL, hasAnthropicCredentials, type Effort } from "./agent/model.js";
import { Trace } from "./agent/trace.js";
import { AUDIENCES, type Audience } from "./fix/intent.js";
import { NoMigrationsError } from "./db/load.js";
import { fixWithAgent, fixWithTemplate, lockColumns, type FixResult } from "./fix/session.js";
import type { Escalation } from "./scan/escalation.js";
import { needsFix, SEVERITY_ORDER, type Finding, type Severity } from "./scan/findings.js";
import {
  prepareProject,
  scanCodeOnly,
  scanPrepared,
  type CodeOnlyResult,
  type ScanOptions,
  type ScanResult,
} from "./scan/index.js";
import { CancelledError, TerminalHuman } from "./ui/human.js";
import { codeOnlyToJson, renderCodeOnly, renderScan, scanToJson, worstSeverity } from "./ui/report.js";

const HELP = `
${pc.bold("vibesecure")} - find and fix security holes in AI-built Supabase apps

${pc.bold("Usage")}
  vibesecure scan [dir]      Test who can reach each table, and check the app's code
                             (no AI, no API key)
  vibesecure fix [dir]       Fix what the scan found, with you approving every change

${pc.bold("Scan options")}
  --json                     Print the full result as JSON
  --fail-on <level>          Exit with code 1 at this severity or worse:
                             critical, high (default), medium, low, none
  --schema <name>            Schema the API exposes (default: public; repeatable)
  --no-default-grants        Simulate Supabase's newer default (Oct 30, 2026): new
                             tables aren't exposed to the API until granted
  --skip-code                Only test the database, not the app's source code

${pc.bold("Fix options")}
  --no-ai                    Use fix templates only, even if an API key is set
  --model <id>               Claude model for the agent (default: ${DEFAULT_MODEL})
  --effort <level>           low, medium (default), high, xhigh or max
  --table <name> --read <who> --write <who> --yes
                             Fix one table with a template, without questions.
                             <who> is one of: ${AUDIENCES.join(", ")}
  --lock <table.column> --yes
                             Stop users from setting a column like profiles.role

The code checks look for XSS, leaked API keys, functions anyone can call without
a login or rate limit, unverified payment webhooks, SQL and filter injection,
SSRF, open redirects and more. To silence one, put a // vibesecure-ignore
comment on that line or the line above.

The agent needs ANTHROPIC_API_KEY. Without it, fix uses templates.
Nothing ever connects to your real database: your migrations are loaded into
an in-memory Postgres, and fixes are saved as new migration files.
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      "fail-on": { type: "string", default: "high" },
      schema: { type: "string", multiple: true },
      "no-default-grants": { type: "boolean", default: false },
      "skip-code": { type: "boolean", default: false },
      lock: { type: "string" },
      "no-ai": { type: "boolean", default: false },
      model: { type: "string", default: DEFAULT_MODEL },
      effort: { type: "string", default: DEFAULT_EFFORT },
      table: { type: "string" },
      read: { type: "string" },
      write: { type: "string" },
      yes: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });

  if (values.version) {
    console.log(packageVersion());
    return 0;
  }
  const [command, dir = "."] = positionals;
  if (values.help || !command) {
    console.log(HELP);
    return values.help ? 0 : 1;
  }

  const projectDir = resolve(dir);
  const scanOptions: ScanOptions = {
    schemas: values.schema,
    defaultGrants: !values["no-default-grants"],
    code: !values["skip-code"],
  };

  if (command === "scan") {
    const failOn = values["fail-on"] as Severity | "none";
    if (failOn !== "none" && !SEVERITY_ORDER.includes(failOn)) throw new UsageError(`Unknown --fail-on level: ${failOn}`);
    const scan = await runScan(projectDir, scanOptions, !values.json);
    try {
      if ("project" in scan) {
        console.log(values.json ? JSON.stringify(scanToJson(scan), null, 2) : renderScan(scan, displayPath(projectDir)));
      } else {
        console.log(values.json ? JSON.stringify(codeOnlyToJson(scan), null, 2) : renderCodeOnly(scan, displayPath(projectDir)));
      }
      const worst = worstSeverity(scan.findings);
      const failed = failOn !== "none" && worst !== null && SEVERITY_ORDER.indexOf(worst) <= SEVERITY_ORDER.indexOf(failOn);
      return failed ? 1 : 0;
    } finally {
      if ("project" in scan) await scan.project.db.close();
    }
  }

  if (command === "fix") {
    const effort = values.effort as Effort;
    if (!["low", "medium", "high", "xhigh", "max"].includes(effort)) throw new UsageError(`Unknown --effort: ${effort}`);
    return runFix(projectDir, scanOptions, {
      ai: !values["no-ai"] && hasAnthropicCredentials(),
      aiRequested: !values["no-ai"],
      model: values.model,
      effort,
      table: values.table,
      read: values.read,
      write: values.write,
      lock: values.lock,
      yes: values.yes,
    });
  }

  throw new UsageError(`Unknown command: ${command}. Use "scan" or "fix".`);
}

/** Scans the database and the code; without migrations, just the code. */
async function runScan(projectDir: string, options: ScanOptions, showSpinner: boolean): Promise<ScanResult | CodeOnlyResult> {
  const spin = showSpinner && process.stdout.isTTY ? clack.spinner() : null;
  spin?.start("Loading your migrations into an in-memory Postgres");
  try {
    const project = await prepareProject(projectDir, options);
    spin?.message("Testing what strangers and other users can do, and checking your code");
    const scan = await scanPrepared(project);
    spin?.stop("Scan complete");
    return scan;
  } catch (error) {
    if (error instanceof NoMigrationsError && options.code !== false) {
      spin?.stop("No Supabase migrations found, so checking the code only");
      return scanCodeOnly(projectDir);
    }
    spin?.stop("Scan failed");
    throw error;
  }
}

interface FixFlags {
  ai: boolean;
  aiRequested: boolean;
  model: string;
  effort: Effort;
  table?: string;
  read?: string;
  write?: string;
  lock?: string;
  yes: boolean;
}

async function runFix(projectDir: string, options: ScanOptions, flags: FixFlags): Promise<number> {
  const human = new TerminalHuman();
  const scanned = await runScan(projectDir, options, true);
  if (!("project" in scanned)) {
    console.log(renderCodeOnly(scanned, displayPath(projectDir)));
    clack.outro("No Supabase migrations found, so there's no database to fix. The report says how to fix each code issue.");
    return 0;
  }
  const scan = scanned;
  try {
    // Non-interactive: lock one column (or every risky column of a table), explicit --yes.
    if (flags.lock) {
      const findTable = (name: string) => scan.project.targets.find((t) => t.kind === "table" && (t.label === name || t.key === name));
      // "profiles.role" is a column; "public.profiles" is a whole table.
      let [table, column] = splitColumn(flags.lock);
      if (!findTable(table) && findTable(flags.lock)) [table, column] = [flags.lock, null];
      const target = findTable(table);
      if (!target) throw new UsageError(`No table called "${table}".`);
      if (column !== null && !target.relation.columns.some((c) => c.name === column)) {
        throw new UsageError(`${target.label} has no column called "${column}".`);
      }
      const group = scan.escalations.filter((e) => e.target.key === target.key && (column === null || e.column.name === column));
      if (group.length === 0) {
        human.success(`Users already can't set ${flags.lock} themselves. Nothing to lock.`);
        return 0;
      }
      const result = await lockColumns(scan, group[0]!.target, group, human, { autoSave: flags.yes });
      if (result.status === "failed") human.warn(result.note ?? "The fix didn't pass.");
      if (result.status === "rejected") human.info("Not saved. Add --yes to save the fix.");
      return result.status === "saved" ? 0 : 1;
    }

    // Non-interactive: one table, a template, explicit intent, explicit --yes.
    if (flags.table) {
      const target = scan.project.targets.find((t) => t.label === flags.table || t.key === flags.table);
      if (!target) throw new UsageError(`No table, view or bucket called "${flags.table}".`);
      const read = audience(flags.read, "--read");
      const write = target.kind === "view" ? "nobody" : audience(flags.write, "--write");
      const result = await fixWithTemplate(scan, target, human, { intent: { read, write }, autoSave: flags.yes });
      if (result.status === "failed") human.warn(result.note ?? "The fix didn't pass.");
      if (result.status === "rejected") human.info("Not saved. Add --yes to save the fix.");
      return result.status === "saved" ? 0 : 1;
    }

    clack.intro(pc.bold("Vibesecure fix"));
    console.log(renderScan(scan, displayPath(projectDir)));
    const targets = scan.project.targets.filter((t) => needsFix(scan.findings, t.key));
    const locks = groupByTable(scan.escalations);
    const manual = scan.findings.filter(isManualFix);
    if (targets.length === 0 && locks.length === 0) {
      clack.outro(manual.length > 0 ? `Nothing to fix automatically. ${manualNote(manual.length)}` : "Nothing to fix. 🎉");
      return 0;
    }

    if (!flags.ai) {
      human.info(
        flags.aiRequested
          ? "No ANTHROPIC_API_KEY found, so fixes will use templates. Set it to let the AI agent help."
          : "Using fix templates (--no-ai).",
      );
    }
    const model = flags.ai ? new AnthropicModel(flags.model, flags.effort) : null;
    const trace = new Trace(join(projectDir, ".vibesecure", "trace.jsonl"));
    const results: FixResult[] = [];

    for (const target of targets) {
      const problems = scan.findings.filter((f) => f.targetKey === target.key).map((f) => `• ${f.title}`);
      human.show(target.kind === "bucket" ? `Bucket: ${target.label}` : target.label, problems.join("\n"));

      const how = await human.choose(`Fix ${target.label}?`, [
        ...(model ? [{ value: "agent", label: "Fix it with the AI agent", hint: "it reads your code and asks you if unsure" }] : []),
        { value: "template", label: model ? "Fix it with a template" : "Fix it", hint: "you choose who can read and write" },
        { value: "skip", label: "Skip" },
      ]);
      if (how === "skip") {
        results.push({ target, status: "skipped" });
        continue;
      }

      let result = how === "agent" ? await fixWithAgent(scan, target, human, model!, trace) : await fixWithTemplate(scan, target, human);
      if (result.status === "failed") {
        human.warn(result.note ?? "No fix was saved.");
        if (how === "agent" && (await human.confirm("Try a template fix instead?"))) {
          result = await fixWithTemplate(scan, target, human);
        }
      }
      results.push(result);
    }

    for (const group of locks) {
      const target = group[0]!.target;
      const columns = group.map((e) => `${target.label}.${e.column.name}`).join(", ");
      const problems = scan.findings.filter((f) => group.some((e) => f.targetKey === `column:${target.key}.${e.column.name}`));
      human.show(`Columns users shouldn't set: ${columns}`, problems.map((f) => `• ${f.title}`).join("\n"));
      const how = await human.choose(`Lock ${columns}?`, [
        { value: "lock", label: "Lock it", hint: "only your server and migrations can change it" },
        { value: "skip", label: "Skip" },
      ]);
      results.push(how === "lock" ? await lockColumns(scan, target, group, human) : { target, status: "skipped" });
      const last = results[results.length - 1]!;
      if (last.status === "failed") human.warn(last.note ?? "No fix was saved.");
    }

    if (manual.length > 0) human.info(manualNote(manual.length));
    summarize(results, projectDir, model !== null);
    return 0;
  } finally {
    await scan.project.db.close();
  }
}

function summarize(results: FixResult[], projectDir: string, usedAgent: boolean): void {
  const saved = results.filter((r) => r.status === "saved");
  if (saved.length === 0) {
    clack.outro("No fixes saved.");
    return;
  }
  const files = saved.map((r) => `  ${relative(projectDir, r.file!)}`).join("\n");
  clack.note(
    [
      "Saved:",
      files,
      "",
      "Apply them to your real database:",
      "  • Own Supabase project: run `supabase db push`, or paste each file into the SQL editor.",
      "  • Lovable Cloud: ask Lovable's chat to run the SQL in each file.",
      "",
      "Then run `vibesecure scan` again to confirm.",
      ...(usedAgent ? ["The agent's full log is in .vibesecure/trace.jsonl."] : []),
    ].join("\n"),
    "Next steps",
  );
  clack.outro(`Saved ${saved.length} fix${saved.length === 1 ? "" : "es"}.`);
}

/** Problems in code and database functions: the report says how to fix them, by hand. */
function isManualFix(finding: Finding): boolean {
  return finding.rule !== "db-access" && finding.code !== "privilege_escalation";
}

function manualNote(count: number): string {
  return `${count} issue${count === 1 ? "" : "s"} in your code or database functions need${count === 1 ? "s" : ""} a change by hand: each one in the report says how.`;
}

function groupByTable(escalations: Escalation[]): Escalation[][] {
  const groups = new Map<string, Escalation[]>();
  for (const e of escalations) groups.set(e.target.key, [...(groups.get(e.target.key) ?? []), e]);
  return [...groups.values()];
}

/** "profiles.role" -> ["profiles", "role"], "public.profiles.role" -> ["public.profiles", "role"], "profiles" -> ["profiles", null]. */
function splitColumn(value: string): [string, string | null] {
  const dot = value.lastIndexOf(".");
  if (dot === -1) return [value, null];
  return [value.slice(0, dot), value.slice(dot + 1)];
}

function audience(value: string | undefined, flag: string): Audience {
  if (!value || !AUDIENCES.includes(value as Audience)) {
    throw new UsageError(`${flag} must be one of: ${AUDIENCES.join(", ")}`);
  }
  return value as Audience;
}

function displayPath(dir: string): string {
  return relative(process.cwd(), dir) || ".";
}

function packageVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
  return pkg.version;
}

class UsageError extends Error {}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    if (error instanceof CancelledError) {
      clack.cancel("Cancelled. Nothing was saved for the current table.");
      process.exit(130);
    }
    const message = error instanceof Error ? error.message : String(error);
    console.error(pc.red(error instanceof UsageError ? message : `Error: ${message}`));
    process.exit(2);
  },
);
