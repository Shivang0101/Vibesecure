import type { ColumnInfo, SchemaInfo } from "../db/introspect.js";
import { quoteLiteral } from "../sql/quote.js";
import { OWASP, type Finding } from "./findings.js";

/** What a privilege column controls, which decides the value we try to give ourselves. */
export type PrivilegeKind = "admin" | "plan" | "balance" | "verified" | "banned";

const KINDS: [PrivilegeKind, RegExp][] = [
  ["banned", /^(?:is_?)?(?:banned|blocked|suspended)$/],
  ["verified", /^(?:is_?)?(?:verified|approved|email_?verified)$/],
  ["balance", /^(?:credits?|balance|tokens?_?balance|coins|points_?balance)$/],
  [
    "plan",
    /^(?:plan|tier|(?:subscription|membership)_?(?:tier|status|plan|level)|is_?(?:premium|pro|paid|vip|subscribed)|premium)$/,
  ],
  [
    "admin",
    /^(?:(?:user_|app_|account_|member_)?roles?|(?:account|user|member)_?type|is_?(?:admin|super_?admin|superuser|staff|moderator|mod)|admin|superuser|staff|moderator|permissions?|access_?level)$/,
  ],
];

/** Columns that decide what a user may do or has paid for: role, is_admin, plan, credits... */
export function privilegeKind(columnName: string): PrivilegeKind | null {
  const name = columnName.toLowerCase();
  return KINDS.find(([, pattern]) => pattern.test(name))?.[0] ?? null;
}

/** Allowed values to try, most powerful first. */
const STRONGEST = [
  /admin|owner|super/i,
  /staff|moderator|editor/i,
  /enterprise|business|premium|pro|paid|vip|unlimited|team|plus/i,
  /verified|approved|active/i,
];

export interface EscalationValue {
  /** SQL literal to write. */
  sql: string;
  /** How Postgres prints it back (`col::text`), to check the write really happened. */
  text: string;
}

/**
 * The value a user would give themselves: the most powerful allowed label
 * ('admin', 'pro'), true for flags, false for "banned", a big balance.
 */
export function escalationValue(column: ColumnInfo, kind: PrivilegeKind): EscalationValue | null {
  const choices = column.enumLabels.length > 0 ? column.enumLabels : column.allowedValues;
  if (choices.length > 0) {
    if (kind === "banned") return null;
    const pick = STRONGEST.map((pattern) => choices.find((v) => pattern.test(v))).find(Boolean) ?? choices[choices.length - 1]!;
    return { sql: quoteLiteral(pick), text: pick };
  }

  const type = column.baseType.toLowerCase();
  if (column.category === "B") return kind === "banned" ? { sql: "false", text: "false" } : { sql: "true", text: "true" };
  if (column.category === "N") return { sql: "1000", text: "1000" };
  if (column.category === "S") {
    const word = { admin: "admin", plan: "pro", verified: "verified", balance: null, banned: null }[kind];
    return word ? { sql: quoteLiteral(word), text: word } : null;
  }
  if (type === "text[]" || type === "character varying[]") return { sql: "array['admin']", text: "{admin}" };
  return null;
}

const PASSWORD_COLUMN = /^(?:password|passwd|pass|pwd|password_?hash|hashed_?password|pass_?hash|user_?password)$/i;

/**
 * Apps sometimes build their own login on a users table instead of using
 * Supabase Auth. Passwords in a table the API can reach are one policy
 * mistake away from being public, and are often stored in plain text.
 */
export function passwordColumnFindings(schema: SchemaInfo): Finding[] {
  const findings: Finding[] = [];
  for (const relation of schema.relations) {
    if (relation.kind !== "table") continue;
    for (const column of relation.columns.filter((c) => PASSWORD_COLUMN.test(c.name))) {
      const label = relation.schema === "public" ? relation.name : `${relation.schema}.${relation.name}`;
      const hashed = /hash/i.test(column.name);
      findings.push({
        severity: hashed ? "medium" : "high",
        targetKey: `column:${relation.schema}.${relation.name}.${column.name}`,
        label: `${label}.${column.name}`,
        title: `${label}.${column.name} keeps passwords in your own table instead of Supabase Auth.`,
        detail: hashed
          ? "One policy mistake makes the hashes public, and then they can be cracked offline."
          : "If they are stored as typed, anyone who can read this table gets every user's password, which people reuse elsewhere.",
        fix: "Sign users in with Supabase Auth (supabase.auth.signUp / signInWithPassword), which hashes passwords and keeps them out of the API, then drop this column.",
        rule: "db-password-column",
        owasp: OWASP.crypto,
      });
    }
  }
  return findings;
}
