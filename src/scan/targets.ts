import type { BucketInfo, RelationInfo, SchemaInfo } from "../db/introspect.js";
import { qualifiedName, quoteLiteral } from "../sql/quote.js";

/** One thing we test access to: a table, a view, or the files in a storage bucket. */
export interface Target {
  /** Stable id, e.g. "public.posts" or "storage:avatars". */
  key: string;
  /** Short name for people, e.g. "posts" or "avatars". */
  label: string;
  kind: "table" | "view" | "bucket";
  relation: RelationInfo;
  /** SQL name of the relation to query, already quoted. */
  sqlName: string;
  ownerColumn: string | null;
  /** Extra condition every query adds (which bucket a file is in). */
  scope: string | null;
  bucket?: BucketInfo;
}

export function buildTargets(schema: SchemaInfo): Target[] {
  const targets: Target[] = schema.relations.map((relation) => ({
    key: `${relation.schema}.${relation.name}`,
    label: relation.schema === "public" ? relation.name : `${relation.schema}.${relation.name}`,
    kind: relation.kind,
    relation,
    sqlName: qualifiedName(relation.schema, relation.name),
    ownerColumn: relation.ownerColumn,
    scope: null,
  }));

  if (schema.storageObjects) {
    for (const bucket of schema.buckets) {
      targets.push({
        key: `storage:${bucket.id}`,
        label: bucket.id,
        kind: "bucket",
        relation: schema.storageObjects,
        sqlName: qualifiedName("storage", "objects"),
        ownerColumn: "owner",
        scope: `bucket_id = ${quoteLiteral(bucket.id)}`,
        bucket,
      });
    }
  }
  return targets;
}

/** Builds a WHERE clause from the target's scope plus any extra conditions. */
export function whereClause(target: Target, ...conditions: (string | null)[]): string {
  const parts = [target.scope, ...conditions].filter((c): c is string => Boolean(c));
  return parts.length > 0 ? `where ${parts.join(" and ")}` : "";
}
