import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Saves an approved fix as a new migration. The name sorts after every
 * existing migration (Supabase applies them in name order), and an existing
 * file is never overwritten.
 */
export function writeMigration(migrationsDir: string, label: string, sql: string, now = new Date()): string {
  const latest = readdirSync(migrationsDir)
    .map((name) => /^(\d{14})_/.exec(name)?.[1])
    .filter((stamp): stamp is string => stamp !== undefined)
    .sort()
    .pop();

  let stamp = timestamp(now);
  if (latest && stamp <= latest) stamp = timestamp(new Date(parseStamp(latest).getTime() + 1000));

  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  const path = join(migrationsDir, `${stamp}_vibesecure_fix_${slug}.sql`);
  writeFileSync(path, sql.endsWith("\n") ? sql : `${sql}\n`, { flag: "wx" });
  return path;
}

function timestamp(date: Date): string {
  return date.toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

function parseStamp(stamp: string): Date {
  const [y, mo, d, h, mi, s] = [0, 4, 6, 8, 10, 12].map((i, n) => stamp.slice(i, n === 0 ? 4 : i + 2));
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
}
