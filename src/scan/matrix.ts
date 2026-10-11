import type { PGliteInterface } from "@electric-sql/pglite";
import { errorMessage } from "../db/load.js";
import { quoteIdent, quoteLiteral } from "../sql/quote.js";
import { privilegeKind } from "./columns.js";
import { insertSql, USERS, type SeedReport, type TestUser } from "./seed.js";
import { whereClause, type Target } from "./targets.js";

export type Principal = "anon" | "other" | "owner";
export type Operation = "read" | "insert" | "update" | "delete";

export const PRINCIPALS: Principal[] = ["anon", "other", "owner"];
export const OPERATIONS: Operation[] = ["read", "insert", "update", "delete"];

export interface OpResult {
  allowed: boolean;
  /** Rows read, updated or deleted. */
  count?: number;
  /** The test hit an error that is not about permissions, so we can't tell. */
  inconclusive?: boolean;
  error?: string;
}

export type AccessRow = Partial<Record<Operation, OpResult>>;
export type TargetAccess = Record<Principal, AccessRow>;

export interface AccessResult {
  target: Target;
  /** False when we couldn't create test rows, so only static checks apply. */
  tested: boolean;
  note?: string;
  access: TargetAccess;
}

/**
 * Who acts in each test. Reads, updates and deletes aim at user A's rows.
 * Inserts create a row owned by user C: anon and B try to do that "as C",
 * and the owner case is C creating their own row.
 */
function actorFor(principal: Principal, op: Operation): TestUser | null {
  if (principal === "anon") return null;
  if (principal === "other") return USERS.B;
  return op === "insert" ? USERS.C : USERS.A;
}

/**
 * Runs SQL exactly like a Supabase API request would: inside a transaction,
 * switched to the `anon` or `authenticated` role, with the JWT claims that
 * auth.uid() reads. Always rolled back, so tests never change the data.
 */
export async function runAs(db: PGliteInterface, actor: TestUser | null, sql: string) {
  const role = actor ? "authenticated" : "anon";
  const claims = actor
    ? { sub: actor.id, role: "authenticated", aud: "authenticated", email: actor.email }
    : { role: "anon" };
  return db.transaction(async (tx) => {
    await tx.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(claims)]);
    await tx.exec(`set local role ${role}`);
    const result = await tx.query<Record<string, unknown>>(sql);
    await tx.rollback();
    return result;
  });
}

function operationsFor(target: Target): Operation[] {
  return target.kind === "view" ? ["read"] : OPERATIONS;
}

export async function measureAccess(
  db: PGliteInterface,
  targets: Target[],
  seed: SeedReport,
): Promise<AccessResult[]> {
  const results: AccessResult[] = [];
  for (const target of targets) {
    const seedFailure = seed.failures.get(target.key);
    if (seedFailure) {
      results.push({
        target,
        tested: false,
        note: `couldn't create test rows: ${seedFailure}`,
        access: { anon: {}, other: {}, owner: {} },
      });
      continue;
    }
    results.push({ target, tested: true, access: await measureTarget(db, target, targets) });
  }
  return results;
}

export async function measureTarget(db: PGliteInterface, target: Target, allTargets: Target[]): Promise<TargetAccess> {
  const access: TargetAccess = { anon: {}, other: {}, owner: {} };
  const ownerFilter = target.ownerColumn
    ? `${quoteIdent(target.ownerColumn)}::text = ${quoteLiteral(USERS.A.id)}`
    : null;
  const where = whereClause(target, ownerFilter);

  for (const principal of PRINCIPALS) {
    for (const op of operationsFor(target)) {
      const actor = actorFor(principal, op);
      let sql: string;
      switch (op) {
        case "read":
          sql = `select count(*)::int as n from ${target.sqlName} ${where}`;
          break;
        case "insert":
          sql = await insertSql(db, target, allTargets, target.ownerColumn ? USERS.C : null, `new-${principal}`);
          break;
        case "update": {
          const column = quoteIdent(updateColumn(target));
          sql = `update ${target.sqlName} set ${column} = ${column} ${where} returning 1`;
          break;
        }
        case "delete":
          sql = `delete from ${target.sqlName} ${where} returning 1`;
          break;
      }
      access[principal][op] = await attempt(db, actor, op, sql);
    }
  }
  return access;
}

async function attempt(db: PGliteInterface, actor: TestUser | null, op: Operation, sql: string): Promise<OpResult> {
  try {
    const result = await runAs(db, actor, sql);
    if (op === "read") {
      const count = Number(result.rows[0]?.n ?? 0);
      return { allowed: count > 0, count };
    }
    if (op === "insert") return { allowed: true, count: 1 };
    return { allowed: result.rows.length > 0, count: result.rows.length };
  } catch (error) {
    const code = (error as { code?: string }).code;
    // 42501 = insufficient privilege, which includes "violates row-level security policy".
    if (code === "42501") return { allowed: false, count: 0 };
    return { allowed: false, inconclusive: true, error: errorMessage(error) };
  }
}

/**
 * A column to "edit" in the update test: an ordinary one, so the edit looks
 * like a real save. Never a privilege column like `role`: those may be locked
 * on purpose, and have their own test (escalation.ts).
 */
function updateColumn(target: Target): string {
  if (target.kind === "bucket") return "name";
  const { columns, primaryKey } = target.relation;
  const plain = columns.find(
    (c) => !c.generated && !primaryKey.includes(c.name) && c.name !== target.ownerColumn && privilegeKind(c.name) === null,
  );
  return (plain ?? columns.find((c) => !c.generated) ?? columns[0]!).name;
}
