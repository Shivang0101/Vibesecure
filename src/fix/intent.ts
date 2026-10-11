import type { AccessRow, OpResult, Operation, TargetAccess } from "../scan/matrix.js";
import type { Target } from "../scan/targets.js";

/** Who should be allowed to do something. */
export type Audience = "nobody" | "owner" | "signed_in" | "anyone";

export const AUDIENCES: Audience[] = ["owner", "signed_in", "anyone", "nobody"];

/** What the founder wants for one table: who may read it, and who may change it. */
export interface Intent {
  read: Audience;
  write: Audience;
}

export interface IntentCheck {
  ok: boolean;
  label: string;
  /** Errors block a fix. Warnings are shown but don't block. */
  level: "error" | "warning";
}

export function describeAudience(audience: Audience, verb: "read" | "change"): string {
  switch (audience) {
    case "anyone":
      return `anyone can ${verb} rows, even without signing in`;
    case "signed_in":
      return `any signed-in user can ${verb} rows`;
    case "owner":
      return `only the row's owner can ${verb} it`;
    case "nobody":
      return `nobody can ${verb} rows through the API (only your server)`;
  }
}

/** Returns a reason if this intent can't apply to the target, otherwise null. */
export function intentProblem(target: Target, intent: Intent): string | null {
  if (!target.ownerColumn && (intent.read === "owner" || intent.write === "owner")) {
    return `${target.label} has no owner column, so "only the owner" can't apply. Choose signed-in users, anyone or nobody.`;
  }
  if (target.kind === "view" && intent.write !== "nobody") {
    return "Views are read-only here; set write to nobody.";
  }
  return null;
}

/**
 * Compares measured access with the intent.
 * Leaks (someone who shouldn't get in, gets in) are errors.
 * The owner losing access is only a warning, because our test rows can't
 * always satisfy policies that depend on other data (like team membership).
 */
export function checkIntent(target: Target, access: TargetAccess, intent: Intent): IntentCheck[] {
  const checks: IntentCheck[] = [];
  const mustBlock = (row: AccessRow, op: Operation, label: string) => checks.push(blocked(row[op], label));
  const shouldAllow = (row: AccessRow, op: Operation, label: string) => checks.push(allowed(row[op], label));

  switch (intent.read) {
    case "anyone":
      shouldAllow(access.owner, "read", "the owner can read their rows");
      break;
    case "signed_in":
      mustBlock(access.anon, "read", "people who aren't signed in can't read rows");
      shouldAllow(access.owner, "read", "the owner can read their rows");
      break;
    case "owner":
      mustBlock(access.anon, "read", "people who aren't signed in can't read other users' rows");
      mustBlock(access.other, "read", "other signed-in users can't read someone else's rows");
      shouldAllow(access.owner, "read", "the owner can read their rows");
      break;
    case "nobody":
      mustBlock(access.anon, "read", "people who aren't signed in can't read rows");
      mustBlock(access.other, "read", "signed-in users can't read rows");
      mustBlock(access.owner, "read", "the API can't read rows at all");
      break;
  }

  if (target.kind === "view") return checks;

  const writes: Operation[] = ["insert", "update", "delete"];
  const verb = (op: Operation) => (op === "insert" ? "add" : op === "update" ? "edit" : "delete");
  switch (intent.write) {
    case "anyone":
      break;
    case "signed_in":
      for (const op of writes) mustBlock(access.anon, op, `people who aren't signed in can't ${verb(op)} rows`);
      shouldAllow(access.owner, "insert", "signed-in users can add rows");
      break;
    case "owner":
      for (const op of writes) mustBlock(access.anon, op, `people who aren't signed in can't ${verb(op)} rows`);
      mustBlock(access.other, "insert", "users can't add rows in someone else's name");
      mustBlock(access.other, "update", "users can't edit someone else's rows");
      mustBlock(access.other, "delete", "users can't delete someone else's rows");
      shouldAllow(access.owner, "insert", "the owner can add their own rows");
      shouldAllow(access.owner, "update", "the owner can edit their rows");
      shouldAllow(access.owner, "delete", "the owner can delete their rows");
      break;
    case "nobody":
      for (const op of writes) {
        mustBlock(access.anon, op, `people who aren't signed in can't ${verb(op)} rows`);
        mustBlock(access.other, op, `signed-in users can't ${verb(op)} rows`);
        mustBlock(access.owner, op, `the API can't ${verb(op)} rows at all`);
      }
      break;
  }
  return checks;
}

function blocked(result: OpResult | undefined, label: string): IntentCheck {
  if (!result) return { ok: true, label, level: "error" };
  if (result.inconclusive) return { ok: false, label: `${label} (couldn't confirm: ${result.error})`, level: "warning" };
  return { ok: !result.allowed, label, level: "error" };
}

function allowed(result: OpResult | undefined, label: string): IntentCheck {
  if (!result) return { ok: true, label, level: "warning" };
  if (result.inconclusive) return { ok: false, label: `${label} (couldn't confirm: ${result.error})`, level: "warning" };
  return { ok: result.allowed, label, level: "warning" };
}

export function passes(checks: IntentCheck[]): boolean {
  return checks.every((c) => c.ok || c.level === "warning");
}
