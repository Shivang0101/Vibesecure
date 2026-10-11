import { relative } from "node:path";
import { runFixAgent, type AgentOutcome } from "../agent/loop.js";
import type { ModelClient } from "../agent/model.js";
import type { SessionState } from "../agent/tools.js";
import type { Trace } from "../agent/trace.js";
import type { ScanResult } from "../scan/index.js";
import type { Target } from "../scan/targets.js";
import type { Choice, HumanIO } from "../ui/human.js";
import { describeAudience, intentProblem, type Audience, type Intent } from "./intent.js";
import { writeMigration } from "./migration.js";
import { findLeakyPolicies, templateSql } from "./templates.js";
import { verifyFix } from "./verify.js";

export interface FixResult {
  target: Target;
  status: "saved" | "skipped" | "rejected" | "failed";
  file?: string;
  note?: string;
}

/** Writes an approved fix next to the other migrations and returns its path. */
export function saveFix(scan: ScanResult, target: Target, sql: string): string {
  return writeMigration(scan.project.load.migrationsDir, target.label, sql);
}

/**
 * The no-AI path: the person says who should read and write, Vibesecure
 * builds the fix from a template, verifies it, and saves it only on "yes".
 */
export async function fixWithTemplate(
  scan: ScanResult,
  target: Target,
  human: HumanIO,
  preset?: { intent: Intent; autoSave: boolean },
): Promise<FixResult> {
  const intent = preset?.intent ?? (await askIntent(target, human));
  const problem = intentProblem(target, intent);
  if (problem) return { target, status: "failed", note: problem };

  human.step(`Finding which policies on ${target.label} let the wrong people in`);
  const { leaky, kept } = await findLeakyPolicies(scan.project, target, intent);
  const sql = templateSql(target, intent, leaky);

  human.step("Testing the fix on a throwaway copy of the database");
  const verification = await verifyFix(scan.project, scan.results, target, intent, sql);

  const checks = verification.checks.map((c) => `${c.ok ? "✓" : c.level === "error" ? "✗" : "!"} ${c.label}`);
  const keptNote = kept.length > 0 ? [`Kept as they are: ${kept.map((p) => `"${p.name}"`).join(", ")}`, ""] : [];
  human.show(
    `Fix for ${target.label}`,
    [sql.trim(), "", ...keptNote, "Checked on a throwaway copy:", ...checks, ...verification.sideEffects.map((s) => `✗ ${s}`), ...verification.problems.map((p) => `✗ ${p}`)].join("\n"),
  );

  if (!verification.ok) {
    return {
      target,
      status: "failed",
      note: "The template didn't pass every check. Try the AI agent, which can write a custom fix.",
    };
  }

  const save = preset?.autoSave ?? (await human.confirm(`Save this fix as a new migration?`));
  if (!save) return { target, status: "rejected" };
  const file = saveFix(scan, target, sql);
  human.success(`Saved ${relative(scan.project.projectDir, file)}`);
  return { target, status: "saved", file };
}

/** The AI path: the Claude agent investigates, asks, tests and proposes; the person decides. */
export async function fixWithAgent(
  scan: ScanResult,
  target: Target,
  human: HumanIO,
  model: ModelClient,
  trace: Trace,
): Promise<FixResult & { outcome: AgentOutcome }> {
  const state: SessionState = { status: "working", questionsAsked: 0 };
  const outcome = await runFixAgent(
    model,
    {
      project: scan.project,
      baseline: scan.results,
      findings: scan.findings,
      target,
      human,
      save: (sql) => saveFix(scan, target, sql),
      state,
    },
    trace,
  );

  const tokens = outcome.usage.input + outcome.usage.cacheRead + outcome.usage.cacheWrite;
  human.info(
    `Agent finished in ${outcome.turns} turn${outcome.turns === 1 ? "" : "s"} ` +
      `(${tokens.toLocaleString()} input tokens, ${outcome.usage.cacheRead.toLocaleString()} of them from cache, ` +
      `${outcome.usage.output.toLocaleString()} output tokens).`,
  );

  switch (outcome.status) {
    case "saved":
      human.success(`Saved ${relative(scan.project.projectDir, outcome.file!)}`);
      return { target, status: "saved", file: outcome.file, outcome };
    case "rejected":
      return { target, status: "rejected", outcome };
    default:
      return { target, status: "failed", note: outcome.message, outcome };
  }
}

async function askIntent(target: Target, human: HumanIO): Promise<Intent> {
  const read = (await human.choose(`Who should be able to see ${what(target)}?`, audienceChoices(target, "read"))) as Audience;
  if (target.kind === "view") return { read, write: "nobody" };
  const write = (await human.choose(
    `Who should be able to add, edit and delete ${what(target)}?`,
    audienceChoices(target, "write"),
  )) as Audience;
  return { read, write };
}

function what(target: Target): string {
  return target.kind === "bucket" ? `files in the "${target.label}" bucket` : `rows in ${target.label}`;
}

function audienceChoices(target: Target, kind: "read" | "write"): Choice[] {
  const verb = kind === "read" ? "read" : "change";
  const choices: Choice[] = [];
  if (target.ownerColumn) {
    choices.push({ value: "owner", label: "Only the owner", hint: describeAudience("owner", verb) });
  }
  choices.push({ value: "signed_in", label: "Any signed-in user", hint: describeAudience("signed_in", verb) });
  if (kind === "read") {
    choices.push({ value: "anyone", label: "Anyone, even without signing in", hint: "public data like blog posts" });
  }
  choices.push({ value: "nobody", label: "Nobody through the app", hint: "only your server or edge functions" });
  return choices;
}
