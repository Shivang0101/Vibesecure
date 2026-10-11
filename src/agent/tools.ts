import type Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import type { Finding } from "../scan/findings.js";
import type { PreparedProject } from "../scan/index.js";
import type { AccessResult, AccessRow, Operation } from "../scan/matrix.js";
import type { Target } from "../scan/targets.js";
import { policiesFor } from "../fix/templates.js";
import { verifyFix, type Verification } from "../fix/verify.js";
import type { Intent } from "../fix/intent.js";
import type { HumanIO } from "../ui/human.js";
import { findUsages } from "./usages.js";

/** Everything the tools can see and do during one table's fix session. */
export interface ToolContext {
  project: PreparedProject;
  baseline: AccessResult[];
  findings: Finding[];
  target: Target;
  human: HumanIO;
  /** Saves an approved fix as a migration and returns its path. */
  save(sql: string): string;
  state: SessionState;
}

export interface SessionState {
  status: "working" | "saved" | "rejected";
  questionsAsked: number;
  savedFile?: string;
}

export interface ToolOutput {
  content: string;
  isError?: boolean;
}

const MAX_QUESTIONS = 2;

const audience = z.enum(["owner", "signed_in", "anyone", "nobody"]);
const inputs = {
  read_table: z.object({ name: z.string() }).strict(),
  find_usages: z.object({ name: z.string() }).strict(),
  ask_human: z.object({ question: z.string().min(1), options: z.array(z.string().min(1)).min(2).max(4) }).strict(),
  test_fix: z.object({ sql: z.string().min(1), read: audience, write: audience }).strict(),
  propose_fix: z
    .object({ sql: z.string().min(1), read: audience, write: audience, summary: z.string().min(1) })
    .strict(),
};

const AUDIENCE_SCHEMA = {
  type: "string",
  enum: ["owner", "signed_in", "anyone", "nobody"],
} as const;

/**
 * Tool definitions sent to Claude. `strict: true` makes the model's arguments
 * match the schema; we still validate them with zod before running anything.
 */
export const TOOLS: Anthropic.Beta.BetaTool[] = [
  {
    name: "read_table",
    description:
      "Read a table, view or storage bucket: its columns, owner column, foreign keys, RLS status, " +
      "current policies, measured access and the problems the scan found. Use it on the target first; " +
      "you can also read related tables (for example profiles, to see how admins are marked).",
    strict: true,
    input_schema: {
      type: "object",
      properties: { name: { type: "string", description: "Name of the table, view or bucket, e.g. posts" } },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: "find_usages",
    description:
      "Find where the app's code reads or writes this table or bucket through supabase-js, with a few " +
      "lines of context. Filters like .eq('user_id', user.id) are strong hints that rows are private.",
    strict: true,
    input_schema: {
      type: "object",
      properties: { name: { type: "string", description: "Name of the table, view or bucket" } },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: "ask_human",
    description:
      "Ask the person one short multiple-choice question when you can't tell what they intend. " +
      "Write it in plain English for someone who may not be technical. At most two questions per table.",
    strict: true,
    input_schema: {
      type: "object",
      properties: {
        question: { type: "string", description: "One short question" },
        options: { type: "array", items: { type: "string" }, description: "2 to 4 short answers" },
      },
      required: ["question", "options"],
      additionalProperties: false,
    },
  },
  {
    name: "test_fix",
    description:
      "Try SQL on a throwaway copy of the database and check it. Returns whether it passed, which " +
      "access rules failed, and any change it caused on other tables. Use it until the fix passes.",
    strict: true,
    input_schema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "The SQL to test" },
        read: { ...AUDIENCE_SCHEMA, description: "Who should be able to read rows" },
        write: { ...AUDIENCE_SCHEMA, description: "Who should be able to add, edit and delete rows" },
      },
      required: ["sql", "read", "write"],
      additionalProperties: false,
    },
  },
  {
    name: "propose_fix",
    description:
      "Show a fix that passed test_fix to the person. They can save it, ask for changes, or reject it.",
    strict: true,
    input_schema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "The exact SQL that passed test_fix" },
        read: { ...AUDIENCE_SCHEMA, description: "Who should be able to read rows" },
        write: { ...AUDIENCE_SCHEMA, description: "Who should be able to add, edit and delete rows" },
        summary: {
          type: "string",
          description: "2-3 plain-English sentences: what was wrong, what the fix changes, and who can do what now",
        },
      },
      required: ["sql", "read", "write", "summary"],
      additionalProperties: false,
    },
  },
];

export async function runTool(name: string, rawInput: unknown, ctx: ToolContext): Promise<ToolOutput> {
  switch (name) {
    case "read_table": {
      const input = inputs.read_table.safeParse(rawInput);
      if (!input.success) return invalid(input.error);
      return readTable(input.data.name, ctx);
    }
    case "find_usages": {
      const input = inputs.find_usages.safeParse(rawInput);
      if (!input.success) return invalid(input.error);
      const target = resolveTarget(input.data.name, ctx);
      if (!target) return unknownName(input.data.name, ctx);
      ctx.human.step(`Looking for ${target.label} in your code`);
      const result = findUsages(ctx.project.projectDir, target.label, target.kind);
      return json(result.total === 0 ? { ...result, note: "No supabase-js calls found for this name." } : result);
    }
    case "ask_human": {
      const input = inputs.ask_human.safeParse(rawInput);
      if (!input.success) return invalid(input.error);
      if (ctx.state.questionsAsked >= MAX_QUESTIONS) {
        return { content: "You've already asked two questions. Decide with what you know.", isError: true };
      }
      ctx.state.questionsAsked++;
      const other = "__other__";
      const choice = await ctx.human.choose(input.data.question, [
        ...input.data.options.map((o) => ({ value: o, label: o })),
        { value: other, label: "Something else (I'll type it)" },
      ]);
      const answer = choice === other ? await ctx.human.ask(input.data.question) : choice;
      return json({ answer });
    }
    case "test_fix": {
      const input = inputs.test_fix.safeParse(rawInput);
      if (!input.success) return invalid(input.error);
      ctx.human.step("Testing a fix on a throwaway copy of the database");
      const verification = await verify(ctx, input.data.sql, input.data);
      ctx.human.step(verification.ok ? "The fix passed every check" : "The fix didn't pass yet");
      return json(summarize(verification));
    }
    case "propose_fix": {
      const input = inputs.propose_fix.safeParse(rawInput);
      if (!input.success) return invalid(input.error);
      return proposeFix(input.data, ctx);
    }
    default:
      return { content: `Unknown tool: ${name}`, isError: true };
  }
}

async function proposeFix(input: z.infer<typeof inputs.propose_fix>, ctx: ToolContext): Promise<ToolOutput> {
  const verification = await verify(ctx, input.sql, input);
  if (!verification.ok) {
    return {
      content: JSON.stringify({ error: "This SQL doesn't pass yet. Use test_fix until it does.", ...summarize(verification) }),
      isError: true,
    };
  }

  const passed = verification.checks.filter((c) => c.ok).map((c) => `✓ ${c.label}`);
  const warnings = verification.checks.filter((c) => !c.ok).map((c) => `! ${c.label}`);
  ctx.human.show(
    `Proposed fix for ${ctx.target.label}`,
    [input.summary, "", input.sql.trim(), "", "Checked on a throwaway copy:", ...passed, ...warnings].join("\n"),
  );

  const decision = await ctx.human.choose("What do you want to do?", [
    { value: "save", label: "Save this fix", hint: "writes a new migration file" },
    { value: "change", label: "Ask for changes" },
    { value: "reject", label: "Reject it" },
  ]);

  if (decision === "save") {
    const file = ctx.save(input.sql);
    ctx.state.status = "saved";
    ctx.state.savedFile = file;
    return json({ saved: file, next: "Done. Reply with one short sentence; don't call more tools." });
  }
  if (decision === "change") {
    const feedback = await ctx.human.ask("What should change?");
    return json({ feedback, next: "Revise the fix, run test_fix, then propose it again." });
  }
  ctx.state.status = "rejected";
  return json({ rejected: true, next: "The person rejected this fix. Stop now; don't propose again." });
}

function verify(ctx: ToolContext, sql: string, intent: Intent): Promise<Verification> {
  return verifyFix(ctx.project, ctx.baseline, ctx.target, { read: intent.read, write: intent.write }, sql);
}

function summarize(v: Verification) {
  return {
    passed: v.ok,
    problems: v.problems,
    failed_checks: v.checks.filter((c) => !c.ok && c.level === "error").map((c) => c.label),
    warnings: v.checks.filter((c) => !c.ok && c.level === "warning").map((c) => c.label),
    side_effects: v.sideEffects,
  };
}

function readTable(name: string, ctx: ToolContext): ToolOutput {
  const target = resolveTarget(name, ctx);
  if (!target) return unknownName(name, ctx);
  ctx.human.step(`Reading ${target.label}`);

  const { relation } = target;
  const measured = ctx.baseline.find((r) => r.target.key === target.key);
  const columns =
    target.kind === "bucket"
      ? undefined
      : relation.columns.map((c) => ({
          name: c.name,
          type: c.type,
          not_null: c.notNull,
          has_default: c.hasDefault,
          ...(c.allowedValues.length > 0 ? { allowed_values: c.allowedValues } : {}),
        }));

  return json({
    name: target.label,
    kind: target.kind,
    sql_name: target.sqlName,
    ...(target.kind === "bucket"
      ? { bucket: target.bucket, note: "Files live in storage.objects; scope every policy with bucket_id." }
      : {}),
    ...(target.kind === "table" ? { rls_enabled: relation.rlsEnabled } : {}),
    ...(target.kind === "view" ? { security_invoker: relation.securityInvoker } : {}),
    owner_column: target.ownerColumn,
    owner_reason: target.kind === "bucket" ? "files are owned by the user whose id is the first folder" : relation.ownerReason,
    columns,
    foreign_keys: relation.foreignKeys.map(
      (fk) => `${fk.columns.join(", ")} -> ${fk.refSchema}.${fk.refTable}(${fk.refColumns.join(", ")})`,
    ),
    policies: policiesFor(target).map((p) => ({
      name: p.name,
      command: p.command,
      roles: p.roles,
      using: p.using,
      with_check: p.withCheck,
      permissive: p.permissive,
    })),
    current_access: measured?.tested
      ? {
          strangers: describeRow(measured.access.anon),
          other_signed_in_users_on_user_As_rows: describeRow(measured.access.other),
          owner: describeRow(measured.access.owner),
        }
      : measured?.note,
    problems: ctx.findings.filter((f) => f.targetKey === target.key).map((f) => `${f.severity}: ${f.title}`),
  });
}

function describeRow(row: AccessRow): string {
  const ops = (["read", "insert", "update", "delete"] as Operation[]).filter((op) => row[op]?.allowed);
  return ops.length > 0 ? ops.join(", ") : "nothing";
}

function resolveTarget(name: string, ctx: ToolContext): Target | undefined {
  const wanted = name.trim().toLowerCase().replace(/^public\./, "");
  return ctx.project.targets.find(
    (t) => t.label.toLowerCase() === wanted || t.key.toLowerCase() === wanted || `storage:${wanted}` === t.key,
  );
}

function unknownName(name: string, ctx: ToolContext): ToolOutput {
  return {
    content: `No table, view or bucket called "${name}". Known names: ${ctx.project.targets.map((t) => t.label).join(", ")}`,
    isError: true,
  };
}

function invalid(error: z.ZodError): ToolOutput {
  return { content: `Invalid input: ${error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`, isError: true };
}

function json(value: unknown): ToolOutput {
  return { content: JSON.stringify(value, null, 2) };
}
