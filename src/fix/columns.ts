import { applySql, cloneDatabase, errorMessage } from "../db/load.js";
import { measureEscalation, type Escalation } from "../scan/escalation.js";
import type { ScanResult } from "../scan/index.js";
import { measureAccess } from "../scan/matrix.js";
import type { Target } from "../scan/targets.js";
import { quoteIdent } from "../sql/quote.js";
import { guardFixSql } from "./guard.js";
import { accessChanges } from "./verify.js";

/**
 * Locks columns like `role` so users can't write them, the way Supabase's
 * docs recommend (column privileges): revoke UPDATE on the table, then grant
 * it back on every other column. INSERT gets the same treatment when users
 * could create a row with the column already set. Afterwards only the
 * service role and migrations can change the locked columns.
 */
export function lockColumnsSql(target: Target, escalations: Escalation[]): string {
  const locked = escalations.map((e) => e.column.name);
  const names = locked.map((c) => `${target.label}.${c}`).join(", ");
  const lines = [
    `-- Vibesecure fix: users can no longer set ${names} themselves.`,
    "-- Only your server (with the service_role key) and migrations can change it.",
    `-- Columns you add to ${target.label} later need their own grant, for example:`,
    `--   grant update (new_column) on table ${target.sqlName} to authenticated;`,
    "",
  ];
  const others = target.relation.columns.filter((c) => !c.generated && !locked.includes(c.name)).map((c) => quoteIdent(c.name));

  for (const privilege of ["update", "insert"] as const) {
    const needed = escalations.some((e) => (privilege === "update" ? e.viaUpdate : e.viaInsert));
    const roles = (["anon", "authenticated"] as const).filter((role) => target.relation.grants[role].includes(privilege));
    if (!needed || roles.length === 0) continue;
    lines.push(`revoke ${privilege} on table ${target.sqlName} from ${roles.join(", ")};`);
    if (others.length > 0) {
      lines.push(`grant ${privilege} (${others.join(", ")}) on table ${target.sqlName} to ${roles.join(", ")};`);
    }
    lines.push("");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export interface LockVerification {
  ok: boolean;
  /** Why the SQL couldn't be tried at all. */
  problems: string[];
  checks: { label: string; ok: boolean }[];
  /** Access that changed anywhere, including on this table, which the fix must not do. */
  sideEffects: string[];
  /** Changes that are the point of the fix, shown as warnings. */
  notes: string[];
}

/** Applies the lock to a throwaway copy, tries the escalation again, and re-runs every access test. */
export async function verifyColumnLock(
  scan: ScanResult,
  target: Target,
  escalations: Escalation[],
  sql: string,
): Promise<LockVerification> {
  const problems = guardFixSql(sql, target);
  if (problems.length > 0) return { ok: false, problems, checks: [], sideEffects: [], notes: [] };

  const copy = await cloneDatabase(scan.project.db);
  try {
    try {
      await applySql(copy, sql);
    } catch (error) {
      return { ok: false, problems: [`The SQL failed to run: ${errorMessage(error)}`], checks: [], sideEffects: [], notes: [] };
    }
    const still = await measureEscalation(copy, scan.project.targets, scan.project.seed, target.key);
    const checks = escalations.map((e) => ({
      label: `Users can't set ${target.label}.${e.column.name} themselves`,
      ok: !still.some((s) => s.column.name === e.column.name),
    }));

    const after = await measureAccess(copy, scan.project.targets, scan.project.seed);
    // A locked column that must be filled in (NOT NULL, no default) means users
    // can't add rows at all any more. For a user_roles table that's the point.
    const required = escalations.filter((e) => e.viaInsert && e.column.notNull && !e.column.hasDefault);
    const changes = accessChanges(scan.results, after, null);
    const expected = changes.filter(
      (c) => required.length > 0 && c.targetKey === target.key && c.op === "insert" && !c.allowed,
    );
    const notes = expected.length > 0
      ? [
          `Users can no longer add rows to ${target.label}: ${required.map((e) => e.column.name).join(", ")} must be filled in and has no default. Add rows from your server instead.`,
        ]
      : [];
    // The point of a lock is that ordinary edits keep working, so say so when they do.
    const ownerEdit = (c: { targetKey: string; principal: string; op: string }) =>
      c.targetKey === target.key && c.principal === "owner" && c.op === "update";
    if (scan.results.find((r) => r.target.key === target.key)?.access.owner.update?.allowed) {
      checks.push({ label: `Users can still edit the rest of their own ${target.label} row`, ok: !changes.some(ownerEdit) });
    }
    const sideEffects = changes.filter((c) => !expected.includes(c) && !ownerEdit(c)).map((c) => c.text);

    return { ok: checks.every((c) => c.ok) && sideEffects.length === 0, problems: [], checks, sideEffects, notes };
  } finally {
    await copy.close();
  }
}
