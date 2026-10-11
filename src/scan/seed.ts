import type { PGliteInterface } from "@electric-sql/pglite";
import type { ForeignKey } from "../db/introspect.js";
import { errorMessage } from "../db/load.js";
import { qualifiedName, quoteIdent, quoteLiteral } from "../sql/quote.js";
import type { Target } from "./targets.js";
import { sampleValue } from "./values.js";

export interface TestUser {
  id: string;
  email: string;
}

/**
 * Three fake users:
 *  A owns one row in every table. Can other people reach A's rows?
 *  B is another signed-in user, the "nosy neighbour".
 *  C has no rows yet, so inserts can be tested without clashing with A's rows.
 */
export const USERS = {
  A: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", email: "user-a@example.com" },
  B: { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", email: "user-b@example.com" },
  C: { id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", email: "user-c@example.com" },
} as const satisfies Record<string, TestUser>;

export interface SeedReport {
  /** Targets we could not create test rows for, with the reason. */
  failures: Map<string, string>;
}

/**
 * Creates the fake users and a row for A and for B in every table.
 * Runs with session_replication_role = replica, which switches off triggers
 * and foreign-key checks, so one awkward table can't block the others.
 */
export async function seedDatabase(db: PGliteInterface, targets: Target[]): Promise<SeedReport> {
  const failures = new Map<string, string>();
  await db.exec("set session_replication_role = replica");
  try {
    const users = Object.values(USERS)
      .map((u) => `(${quoteLiteral(u.id)}, ${quoteLiteral(u.email)}, 'authenticated', 'authenticated', now())`)
      .join(", ");
    await db.exec(
      `insert into auth.users (id, email, aud, role, email_confirmed_at) values ${users} on conflict (id) do nothing`,
    );

    for (const target of orderByForeignKeys(targets.filter((t) => t.kind === "table"))) {
      const rows: [TestUser | null, string][] = target.ownerColumn
        ? [[USERS.A, "a"], [USERS.B, "b"]]
        : [[null, "1"], [null, "2"]];
      for (const [owner, tag] of rows) {
        try {
          await db.exec(await insertSql(db, target, targets, owner, tag));
        } catch (error) {
          failures.set(target.key, errorMessage(error));
          break;
        }
      }
    }

    for (const target of targets.filter((t) => t.kind === "bucket")) {
      for (const [owner, tag] of [[USERS.A, "a"], [USERS.B, "b"]] as const) {
        await db.exec(await insertSql(db, target, targets, owner, tag));
      }
    }
  } finally {
    await db.exec("set session_replication_role = default");
  }
  return { failures };
}

/**
 * Builds an INSERT for one test row. Columns with defaults or that allow
 * NULL are left out, so the database fills them in the usual way.
 */
export async function insertSql(
  db: PGliteInterface,
  target: Target,
  allTargets: Target[],
  owner: TestUser | null,
  tag: string,
): Promise<string> {
  const values = new Map<string, string>();

  if (target.kind === "bucket") {
    const id = owner?.id ?? USERS.A.id;
    values.set("bucket_id", quoteLiteral(target.bucket!.id));
    // Path-based policies check the first folder, so files go in "<user id>/".
    values.set("name", quoteLiteral(`${id}/vibesecure-${tag}.txt`));
    values.set("owner", quoteLiteral(id));
    values.set("owner_id", quoteLiteral(id));
  } else {
    for (const column of target.relation.columns) {
      if (column.generated) continue;
      if (column.name === target.ownerColumn && owner) {
        values.set(column.name, quoteLiteral(owner.id));
        continue;
      }
      const fk = target.relation.foreignKeys.find((f) => f.columns.length === 1 && f.columns[0] === column.name);
      if (fk) {
        const ref = await referencedValue(db, fk, allTargets, owner);
        if (ref !== null) {
          values.set(column.name, ref);
          continue;
        }
      }
      if (column.hasDefault || !column.notNull) continue;
      const value = sampleValue(column, tag);
      if (value !== null) values.set(column.name, value);
    }
  }

  const columns = [...values.keys()].map(quoteIdent).join(", ");
  const exprs = [...values.values()].join(", ");
  return columns.length > 0
    ? `insert into ${target.sqlName} (${columns}) values (${exprs})`
    : `insert into ${target.sqlName} default values`;
}

/**
 * Picks an existing row for a foreign key, preferring one owned by the same
 * user, so policies that follow the key (todo -> list -> owner) see sane data.
 */
async function referencedValue(
  db: PGliteInterface,
  fk: ForeignKey,
  allTargets: Target[],
  owner: TestUser | null,
): Promise<string | null> {
  if (fk.refSchema === "auth" && fk.refTable === "users") {
    return quoteLiteral((owner ?? USERS.A).id);
  }
  const refName = qualifiedName(fk.refSchema, fk.refTable);
  const refColumn = quoteIdent(fk.refColumns[0]!);
  const refTarget = allTargets.find((t) => t.key === `${fk.refSchema}.${fk.refTable}`);

  if (owner && refTarget?.ownerColumn) {
    const own = await db.query<{ v: string }>(
      `select ${refColumn}::text as v from ${refName} where ${quoteIdent(refTarget.ownerColumn)}::text = $1 limit 1`,
      [owner.id],
    );
    if (own.rows[0]) return quoteLiteral(own.rows[0].v);
  }
  const any = await db.query<{ v: string }>(`select ${refColumn}::text as v from ${refName} limit 1`);
  return any.rows[0] ? quoteLiteral(any.rows[0].v) : null;
}

/** Parents before children, so foreign keys can point at rows that exist. */
function orderByForeignKeys(tables: Target[]): Target[] {
  const byKey = new Map(tables.map((t) => [t.key, t]));
  const remaining = new Set(tables.map((t) => t.key));
  const ordered: Target[] = [];

  while (remaining.size > 0) {
    const ready = [...remaining].filter((key) =>
      byKey.get(key)!.relation.foreignKeys.every((fk) => {
        const parent = `${fk.refSchema}.${fk.refTable}`;
        return parent === key || !remaining.has(parent);
      }),
    );
    // A cycle of foreign keys: take the rest in name order (FK checks are off).
    const batch = ready.length > 0 ? ready : [...remaining].sort();
    for (const key of batch) {
      ordered.push(byKey.get(key)!);
      remaining.delete(key);
    }
  }
  return ordered;
}
