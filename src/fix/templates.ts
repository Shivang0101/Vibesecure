import { cloneDatabase } from "../db/load.js";
import type { PolicyInfo } from "../db/introspect.js";
import { measureTarget } from "../scan/matrix.js";
import type { PreparedProject } from "../scan/index.js";
import type { Target } from "../scan/targets.js";
import { quoteIdent, quoteLiteral } from "../sql/quote.js";
import { checkIntent, describeAudience, type Audience, type Intent } from "./intent.js";

/**
 * Finds which existing policies cause the leak. Each permissive policy is
 * tested on its own, in a throwaway copy with RLS on and the other policies
 * removed. A policy is "leaky" if on its own it already lets the wrong people
 * in. Safe policies (like an admin-only rule) are kept as they are.
 */
export async function findLeakyPolicies(
  project: PreparedProject,
  target: Target,
  intent: Intent,
): Promise<{ leaky: PolicyInfo[]; kept: PolicyInfo[] }> {
  const policies = policiesFor(target);
  const permissive = policies.filter((p) => p.permissive);
  const leaky: PolicyInfo[] = [];

  for (const policy of permissive) {
    const copy = await cloneDatabase(project.db);
    try {
      if (target.kind !== "view") {
        await copy.exec(`alter table ${target.sqlName} enable row level security`);
      }
      for (const other of permissive) {
        if (other !== policy) await copy.exec(`drop policy ${quoteIdent(other.name)} on ${target.sqlName}`);
      }
      const access = await measureTarget(copy, target, project.targets);
      const leaks = checkIntent(target, access, intent).some((c) => !c.ok && c.level === "error");
      if (leaks) leaky.push(policy);
    } finally {
      await copy.close();
    }
  }
  return { leaky, kept: policies.filter((p) => !leaky.includes(p)) };
}

/** Policies that matter for a target. For a bucket, only those that mention it. */
export function policiesFor(target: Target): PolicyInfo[] {
  if (target.kind !== "bucket") return target.relation.policies;
  const id = target.bucket!.id;
  return target.relation.policies.filter((p) => {
    const exprs = [p.using, p.withCheck].filter((e): e is string => e !== null);
    // Relevant if it names this bucket, or doesn't filter by bucket at all.
    return exprs.length === 0 || exprs.some((e) => e.includes(`'${id}'`) || !e.includes("bucket_id"));
  });
}

/**
 * Writes the SQL for a standard fix: turn RLS on, drop the leaky policies,
 * and add policies that match the intent. Uses `(select auth.uid())`, which
 * Postgres evaluates once per query instead of once per row.
 */
export function templateSql(target: Target, intent: Intent, drop: PolicyInfo[]): string {
  const lines: string[] = [
    `-- Vibesecure fix for ${target.kind === "bucket" ? `the "${target.label}" bucket` : target.label}`,
    `-- Read:  ${describeAudience(intent.read, "read")}`,
  ];
  if (target.kind !== "view") lines.push(`-- Write: ${describeAudience(intent.write, "change")}`);
  lines.push("");

  if (target.kind === "view") {
    if (intent.read === "nobody") {
      lines.push(`revoke select on ${target.sqlName} from anon, authenticated;`);
    } else {
      lines.push("-- Make the view respect the RLS of the tables it reads.");
      lines.push(`alter view ${target.sqlName} set (security_invoker = on);`);
    }
    return `${lines.join("\n")}\n`;
  }

  if (target.kind === "table") {
    lines.push(`alter table ${target.sqlName} enable row level security;`, "");
  }

  if (drop.length > 0) {
    lines.push("-- These policies let the wrong people in:");
    for (const policy of drop) {
      lines.push(`drop policy if exists ${quoteIdent(policy.name)} on ${target.sqlName};`);
    }
    lines.push("");
  }

  const prefix = target.kind === "bucket" ? `vibesecure: ${target.label}: ` : "vibesecure: ";
  const policy = (name: string, command: string, audience: Audience, clause: string) => {
    const roles = audience === "anyone" ? "anon, authenticated" : "authenticated";
    lines.push(
      `create policy ${quoteIdent(prefix + name)} on ${target.sqlName}`,
      `  for ${command} to ${roles}`,
      `  ${clause};`,
      "",
    );
  };

  const rowCheck = (audience: Audience) => scoped(target, audience === "owner" ? ownerCheck(target) : null);

  if (intent.read !== "nobody") {
    policy(`${who(intent.read)} can read`, "select", intent.read, `using (${rowCheck(intent.read)})`);
  }
  if (intent.write !== "nobody") {
    const check = rowCheck(intent.write);
    policy(`${who(intent.write)} can add`, "insert", intent.write, `with check (${check})`);
    policy(`${who(intent.write)} can edit`, "update", intent.write, `using (${check})\n  with check (${check})`);
    policy(`${who(intent.write)} can delete`, "delete", intent.write, `using (${check})`);
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

function who(audience: Audience): string {
  return audience === "owner" ? "owners" : audience === "signed_in" ? "signed-in users" : "anyone";
}

/** The condition "this row belongs to the person asking". */
function ownerCheck(target: Target): string {
  if (target.kind === "bucket") {
    // Supabase's recommended layout: each user's files live in a folder named after their id.
    return "(storage.foldername(name))[1] = (select auth.uid())::text";
  }
  const column = target.relation.columns.find((c) => c.name === target.ownerColumn)!;
  const ident = quoteIdent(column.name);
  return column.baseType === "uuid" ? `(select auth.uid()) = ${ident}` : `(select auth.uid())::text = ${ident}::text`;
}

/** Buckets share one table, so every bucket policy names its bucket. */
function scoped(target: Target, condition: string | null): string {
  const parts = [target.kind === "bucket" ? `bucket_id = ${quoteLiteral(target.bucket!.id)}` : null, condition]
    .filter((p): p is string => p !== null);
  return parts.length > 0 ? parts.join(" and ") : "true";
}
