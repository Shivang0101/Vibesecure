import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { PGlite, type Extension, type PGliteInterface } from "@electric-sql/pglite";
import { splitSqlStatements, stripSqlComments } from "../sql/split.js";
import { supabaseShimSql, type ShimOptions } from "./shim.js";

export interface SkippedStatement {
  file: string;
  statement: string;
  error: string;
}

export interface LoadReport {
  migrationsDir: string;
  files: string[];
  statementCount: number;
  skipped: SkippedStatement[];
  extensions: string[];
}

export interface LoadedDatabase {
  db: PGliteInterface;
  report: LoadReport;
}

/** Postgres extensions PGlite can load, keyed by the name used in `create extension`. */
const EXTENSION_LOADERS: Record<string, () => Promise<Extension>> = {
  "uuid-ossp": async () => (await import("@electric-sql/pglite/contrib/uuid_ossp")).uuid_ossp,
  pgcrypto: async () => (await import("@electric-sql/pglite/contrib/pgcrypto")).pgcrypto,
  citext: async () => (await import("@electric-sql/pglite/contrib/citext")).citext,
  pg_trgm: async () => (await import("@electric-sql/pglite/contrib/pg_trgm")).pg_trgm,
  hstore: async () => (await import("@electric-sql/pglite/contrib/hstore")).hstore,
  ltree: async () => (await import("@electric-sql/pglite/contrib/ltree")).ltree,
  unaccent: async () => (await import("@electric-sql/pglite/contrib/unaccent")).unaccent,
  moddatetime: async () => (await import("@electric-sql/pglite/contrib/moddatetime")).moddatetime,
  fuzzystrmatch: async () => (await import("@electric-sql/pglite/contrib/fuzzystrmatch")).fuzzystrmatch,
  btree_gin: async () => (await import("@electric-sql/pglite/contrib/btree_gin")).btree_gin,
  btree_gist: async () => (await import("@electric-sql/pglite/contrib/btree_gist")).btree_gist,
  cube: async () => (await import("@electric-sql/pglite/contrib/cube")).cube,
  earthdistance: async () => (await import("@electric-sql/pglite/contrib/earthdistance")).earthdistance,
  vector: async () => (await import("@electric-sql/pglite-pgvector")).vector,
};

/** Finds `supabase/migrations/*.sql`, oldest first (Supabase names them by timestamp). */
export function findMigrationFiles(projectDir: string): { dir: string; files: string[] } {
  const root = resolve(projectDir);
  const candidates = [join(root, "supabase", "migrations"), root];
  for (const dir of candidates) {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) continue;
    const files = readdirSync(dir)
      .filter((name) => name.endsWith(".sql"))
      .sort()
      .map((name) => join(dir, name));
    if (files.length > 0) return { dir, files };
  }
  throw new NoMigrationsError(
    `No migrations found. Expected SQL files in ${join(root, "supabase", "migrations")}.`,
  );
}

/** The project has no Supabase migrations, so only its code can be checked. */
export class NoMigrationsError extends Error {}

/** Which loadable extensions the migrations ask for, so we only load those. */
export function requestedExtensions(sqlTexts: string[]): string[] {
  const wanted = new Set<string>();
  const pattern = /create\s+extension\s+(?:if\s+not\s+exists\s+)?"?([a-z0-9_-]+)"?/gi;
  for (const sql of sqlTexts) {
    for (const match of sql.matchAll(pattern)) {
      const name = match[1]!.toLowerCase();
      if (EXTENSION_LOADERS[name]) wanted.add(name);
    }
  }
  return [...wanted].sort();
}

/**
 * Settings every session needs. Stored on the database too, so clones made
 * with `db.clone()` start with them.
 *  - search_path: Supabase puts extension functions in the `extensions` schema.
 *  - check_function_bodies: lets functions that mention unsupported objects
 *    (pg_net, pg_cron, ...) still be created, the way pg_dump restores do.
 */
export async function prepareSession(db: PGliteInterface): Promise<void> {
  await db.exec(`
    set search_path = "$user", public, extensions;
    set check_function_bodies = off;
  `);
}

/**
 * Builds a throwaway in-memory Postgres that looks like the project's
 * Supabase database: the Supabase shim first, then every migration in order.
 * Nothing here ever connects to a real database.
 */
export async function loadProjectDatabase(
  projectDir: string,
  options: ShimOptions = { defaultGrants: true },
): Promise<LoadedDatabase> {
  const { dir, files } = findMigrationFiles(projectDir);
  const sources = files.map((file) => ({ file, sql: readFileSync(file, "utf8") }));
  const extensionNames = requestedExtensions(sources.map((s) => s.sql));

  const extensions: Record<string, Extension> = {};
  for (const name of extensionNames) {
    extensions[name.replace(/-/g, "_")] = await EXTENSION_LOADERS[name]!();
  }

  const db = await PGlite.create({ extensions });
  await db.exec(`
    alter database postgres set search_path = "$user", public, extensions;
    alter database postgres set check_function_bodies = off;
  `);
  await prepareSession(db);
  await db.exec(supabaseShimSql(options));

  const report: LoadReport = {
    migrationsDir: dir,
    files: files.map((f) => f.slice(dir.length + 1)),
    statementCount: 0,
    skipped: [],
    extensions: extensionNames,
  };

  for (const { file, sql } of sources) {
    const name = file.slice(dir.length + 1);
    const statements = splitSqlStatements(sql);
    report.statementCount += statements.length;
    try {
      // Fast path: the whole file at once (Postgres runs it all-or-nothing).
      await db.exec(sql);
    } catch {
      // Slow path: one statement at a time, skipping only what fails.
      for (const statement of statements) {
        if (isTransactionControl(statement)) continue;
        try {
          await db.exec(statement);
        } catch (error) {
          report.skipped.push({ file: name, statement: preview(statement), error: errorMessage(error) });
        }
      }
    }
  }

  return { db, report };
}

/** Applies extra SQL (a proposed fix) on top of a loaded database. */
export async function applySql(db: PGliteInterface, sql: string): Promise<void> {
  await db.transaction(async (tx) => {
    for (const statement of splitSqlStatements(sql)) {
      if (isTransactionControl(statement)) continue;
      await tx.exec(statement);
    }
  });
}

/** An independent copy, so a proposed fix can be tested without touching the original. */
export async function cloneDatabase(db: PGliteInterface): Promise<PGliteInterface> {
  const copy = await db.clone();
  await prepareSession(copy);
  return copy;
}

function isTransactionControl(statement: string): boolean {
  return /^(begin|commit|rollback|end|start\s+transaction)\b/i.test(stripSqlComments(statement));
}

function preview(statement: string): string {
  const flat = stripSqlComments(statement);
  return flat.length > 160 ? `${flat.slice(0, 157)}...` : flat;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
