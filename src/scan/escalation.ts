import type { PGliteInterface } from "@electric-sql/pglite";
import type { ColumnInfo, RelationInfo } from "../db/introspect.js";
import { quoteIdent, quoteLiteral } from "../sql/quote.js";
import { escalationValue, privilegeKind, type EscalationValue, type PrivilegeKind } from "./columns.js";
import { OWASP, type Finding, type Severity } from "./findings.js";
import type { DatabaseFunction } from "./functions.js";
import { runAs } from "./matrix.js";
import { insertSql, USERS, type SeedReport } from "./seed.js";
import { whereClause, type Target } from "./targets.js";

export interface Escalation {
  target: Target;
  column: ColumnInfo;
  kind: PrivilegeKind;
  value: EscalationValue;
  /** The owner can set the column on their existing row. */
  viaUpdate: boolean;
  /** A user can create a row with the column already set. */
  viaInsert: boolean;
}

/**
 * Can users give themselves more rights? For every column like `role`,
 * `is_admin`, `plan` or `credits`, user A tries to set it on their own row
 * and user C tries to create a row with it set. A policy that only checks
 * `auth.uid() = id` allows both, which is the classic way people make
 * themselves admin. The value is read back, so triggers that undo the
 * change, column grants and WITH CHECK rules all count as protection.
 */
export async function measureEscalation(
  db: PGliteInterface,
  targets: Target[],
  seed: SeedReport,
  onlyKey?: string,
): Promise<Escalation[]> {
  const found: Escalation[] = [];
  for (const target of targets) {
    if (onlyKey !== undefined && target.key !== onlyKey) continue;
    if (target.kind !== "table" || !target.ownerColumn || seed.failures.has(target.key)) continue;
    for (const column of target.relation.columns) {
      if (column.generated || column.name === target.ownerColumn || target.relation.primaryKey.includes(column.name)) continue;
      const kind = privilegeKind(column.name);
      const value = kind ? escalationValue(column, kind) : null;
      if (!kind || !value) continue;
      const viaUpdate = await triesUpdate(db, target, column, value);
      const viaInsert = await triesInsert(db, target, targets, column, value);
      if (viaUpdate || viaInsert) found.push({ target, column, kind, value, viaUpdate, viaInsert });
    }
  }
  return found;
}

async function triesUpdate(db: PGliteInterface, target: Target, column: ColumnInfo, value: EscalationValue): Promise<boolean> {
  const name = quoteIdent(column.name);
  const where = whereClause(target, `${quoteIdent(target.ownerColumn!)}::text = ${quoteLiteral(USERS.A.id)}`);
  const sql = `update ${target.sqlName} set ${name} = ${value.sql} ${where} returning ${name}::text as v`;
  return succeeded(db, USERS.A, sql, value);
}

async function triesInsert(
  db: PGliteInterface,
  target: Target,
  targets: Target[],
  column: ColumnInfo,
  value: EscalationValue,
): Promise<boolean> {
  const insert = await insertSql(db, target, targets, USERS.C, "escalate", { [column.name]: value.sql });
  return succeeded(db, USERS.C, `${insert} returning ${quoteIdent(column.name)}::text as v`, value);
}

/** True only when the write went through and the value stuck. Any error counts as blocked. */
async function succeeded(
  db: PGliteInterface,
  actor: (typeof USERS)[keyof typeof USERS],
  sql: string,
  value: EscalationValue,
): Promise<boolean> {
  try {
    const result = await runAs(db, actor, sql);
    return result.rows.some((row) => row.v === value.text);
  } catch {
    return false;
  }
}

const PROMISE: Record<PrivilegeKind, string> = {
  admin: "make themselves admin",
  plan: "upgrade themselves for free",
  balance: "give themselves credit",
  verified: "mark themselves as verified",
  banned: "unban themselves",
};

const CONSEQUENCE: Record<PrivilegeKind, string> = {
  admin: "Any admin pages or admin-only data in your app are open to whoever does this.",
  plan: "Paid features your app unlocks from this column become free.",
  balance: "Anything your app sells for credits becomes free.",
  verified: "Your app can no longer trust this flag.",
  banned: "Bans stop working.",
};

export function escalationFindings(
  escalations: Escalation[],
  relations: RelationInfo[],
  functions: DatabaseFunction[],
): Finding[] {
  return escalations.map((e) => {
    const column = `${e.target.label}.${e.column.name}`;
    const setting = `${column} = ${e.value.sql}`;
    const how =
      e.viaUpdate && e.viaInsert
        ? `by setting ${setting} on their own row, or on a new one`
        : e.viaUpdate
          ? `by setting ${setting} on their own row`
          : `by adding a row with ${setting}`;
    const trustedBy = trustedIn(e, relations, functions);
    const severity: Severity = trustedBy.length > 0 ? "critical" : "high";
    return {
      severity,
      targetKey: `column:${e.target.key}.${e.column.name}`,
      label: column,
      title: `Users can ${PROMISE[e.kind]} ${how}.`,
      detail:
        trustedBy.length > 0
          ? `Your access rules trust this column (${trustedBy.join(", ")}), so this unlocks other people's data too.`
          : CONSEQUENCE[e.kind],
      fix: `Run \`vibesecure fix --lock ${column} --yes\`: it revokes ${e.viaInsert && !e.viaUpdate ? "insert" : "update"} on ${e.target.label} and grants it back for every other column, so only your server can change ${e.column.name}.`,
      rule: "db-privilege-escalation",
      owasp: OWASP.accessControl,
      code: "privilege_escalation",
    };
  });
}

/**
 * Policies, and database functions used by policies, that read the column.
 * If `is_admin()` checks `profiles.role`, writing your own role is game over.
 */
function trustedIn(e: Escalation, relations: RelationInfo[], functions: DatabaseFunction[]): string[] {
  const column = new RegExp(`\\b${escapeRegex(e.column.name)}\\b`, "i");
  const table = new RegExp(`\\b${escapeRegex(e.target.relation.name)}\\b`, "i");
  // auth.role() and auth.jwt() ->> 'role' are about the login token, not this column.
  const code = (sql: string) => sql.replace(/'(?:[^']|'')*'/g, "''").replace(/auth\.role\(\)/gi, "");
  const mentions = (sql: string) => column.test(code(sql)) && table.test(code(sql));
  const names: string[] = [];

  const helpers = functions.filter((f) => mentions(f.body));
  for (const relation of relations) {
    for (const policy of relation.policies) {
      const exprs = [policy.using, policy.withCheck].filter((x): x is string => x !== null).join(" ");
      const ownTable = relation === e.target.relation && column.test(code(exprs));
      const helper = helpers.find((f) => new RegExp(`\\b${escapeRegex(f.name)}\\s*\\(`, "i").test(exprs));
      if (ownTable || helper || mentions(exprs)) {
        const label = helper ? `${helper.name}()` : `policy "${policy.name}"`;
        if (!names.includes(label)) names.push(label);
      }
    }
  }
  return names;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
