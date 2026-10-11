import { applySql, cloneDatabase, errorMessage } from "../db/load.js";
import type { PreparedProject } from "../scan/index.js";
import { measureAccess, type AccessResult, type Operation, type Principal, type TargetAccess } from "../scan/matrix.js";
import type { Target } from "../scan/targets.js";
import { guardFixSql } from "./guard.js";
import { checkIntent, intentProblem, passes, type Intent, type IntentCheck } from "./intent.js";

export interface Verification {
  ok: boolean;
  /** Why the SQL couldn't be tried at all: refused by the guard, or it failed to run. */
  problems: string[];
  /** The intent, checked one rule at a time against the new access. */
  checks: IntentCheck[];
  /** Access that changed on *other* tables, which a fix must never do. */
  sideEffects: string[];
  after?: TargetAccess;
}

/**
 * The verifier decides whether a fix is good, never the AI.
 * It applies the SQL to a fresh copy of the database, re-runs every access
 * test, checks the target against the intent, and checks nothing else moved.
 */
export async function verifyFix(
  project: PreparedProject,
  baseline: AccessResult[],
  target: Target,
  intent: Intent,
  sql: string,
): Promise<Verification> {
  const problems = guardFixSql(sql, target);
  const mismatch = intentProblem(target, intent);
  if (mismatch) problems.push(mismatch);
  if (problems.length > 0) return { ok: false, problems, checks: [], sideEffects: [] };

  const copy = await cloneDatabase(project.db);
  try {
    try {
      await applySql(copy, sql);
    } catch (error) {
      return { ok: false, problems: [`The SQL failed to run: ${errorMessage(error)}`], checks: [], sideEffects: [] };
    }
    const after = await measureAccess(copy, project.targets, project.seed);
    const mine = after.find((r) => r.target.key === target.key)!;
    const checks = checkIntent(target, mine.access, intent);
    const sideEffects = compareOthers(baseline, after, target.key);
    return {
      ok: passes(checks) && sideEffects.length === 0,
      problems: [],
      checks,
      sideEffects,
      after: mine.access,
    };
  } finally {
    await copy.close();
  }
}

const WHO: Record<Principal, string> = {
  anon: "people who aren't signed in",
  other: "other signed-in users",
  owner: "the owner",
};

const VERB: Record<Operation, string> = { read: "read", insert: "add", update: "edit", delete: "delete" };

function compareOthers(before: AccessResult[], after: AccessResult[], skipKey: string): string[] {
  return accessChanges(before, after, skipKey).map((c) => c.text);
}

export interface AccessChange {
  targetKey: string;
  principal: Principal;
  op: Operation;
  /** Allowed after the fix. */
  allowed: boolean;
  text: string;
}

/** Every access test whose answer changed, except on `skipKey`. */
export function accessChanges(before: AccessResult[], after: AccessResult[], skipKey: string | null): AccessChange[] {
  const changes: AccessChange[] = [];
  for (const old of before) {
    if (old.target.key === skipKey || !old.tested) continue;
    const now = after.find((r) => r.target.key === old.target.key);
    if (!now) continue;
    for (const principal of Object.keys(WHO) as Principal[]) {
      for (const op of Object.keys(VERB) as Operation[]) {
        const was = old.access[principal][op];
        const is = now.access[principal][op];
        if (!was || !is || was.inconclusive || is.inconclusive) continue;
        if (was.allowed !== is.allowed) {
          changes.push({
            targetKey: old.target.key,
            principal,
            op,
            allowed: is.allowed,
            text: `${old.target.label}: ${WHO[principal]} ${is.allowed ? "can now" : "can no longer"} ${VERB[op]} rows`,
          });
        }
      }
    }
  }
  return changes;
}
