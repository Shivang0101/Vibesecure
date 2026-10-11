import type { ColumnInfo } from "../db/introspect.js";
import { quoteLiteral } from "../sql/quote.js";

/**
 * Returns a SQL expression with a believable value for a column, used when
 * we create test rows. `tag` makes text values unique ("a", "b", "new"...).
 * Returns null when we have no safe guess; the column is then left out.
 */
export function sampleValue(column: ColumnInfo, tag: string): string | null {
  if (column.allowedValues.length > 0) return quoteLiteral(column.allowedValues[0]!);
  if (column.enumLabels.length > 0) return quoteLiteral(column.enumLabels[0]!);

  const type = column.baseType.toLowerCase();
  const name = column.name.toLowerCase();

  if (type === "uuid") return "gen_random_uuid()";
  if (type.endsWith("[]")) return "'{}'";
  if (type === "json" || type === "jsonb") return "'{}'";
  if (type.startsWith("vector(")) return quoteLiteral(zeroVector(type));
  if (type === "bytea") return "'\\x00'";
  if (type === "tsvector") return "''";

  switch (column.category) {
    case "S":
      return quoteLiteral(fitLength(textFor(name, tag), type));
    case "N":
      return "1";
    case "B":
      // false keeps flags like is_public or is_admin at their safest value
      return "false";
    case "D":
      if (type === "date") return "current_date";
      if (type.startsWith("time ")) return "current_time"; // "time without time zone", not "timestamp..."
      return "now()";
    case "T":
      return "'1 hour'";
    case "I":
      return "'127.0.0.1'";
    default:
      return null;
  }
}

function textFor(name: string, tag: string): string {
  if (name.includes("email")) return `vibesecure-${tag}@example.com`;
  if (/(url|link|website|avatar|image|photo)/.test(name)) return `https://example.com/vibesecure-${tag}`;
  if (name.includes("phone")) return `+1555${String(numberFor(tag)).padStart(7, "0")}`;
  if (name.includes("slug") || name.includes("username") || name.includes("handle")) return `vibesecure-${tag}`;
  return `vibesecure test ${name} ${tag}`;
}

/** A small stable number per tag, so generated phone numbers stay unique. */
function numberFor(tag: string): number {
  let hash = 0;
  for (const ch of tag) hash = (hash * 31 + ch.charCodeAt(0)) % 10_000_000;
  return hash;
}

/** Respects varchar(n) / char(n) limits. */
function fitLength(value: string, type: string): string {
  const match = /\((\d+)\)$/.exec(type);
  if (!match) return value;
  const max = Number(match[1]);
  return value.length > max ? value.slice(value.length - max) : value;
}

function zeroVector(type: string): string {
  const dims = Number(/\((\d+)\)/.exec(type)?.[1] ?? "3");
  return `[${new Array(dims).fill(0).join(",")}]`;
}
