import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanProject } from "../src/scan/index.js";
import { letters } from "./helpers.js";

/** The kind of schema AI apps have: uuid-ossp ids, pgvector embeddings, and an extension PGlite lacks. */
const MIGRATION = `
create extension if not exists "uuid-ossp" with schema extensions;
create extension if not exists vector with schema extensions;
create extension if not exists pg_net;

create type public.doc_status as enum ('draft', 'indexed');

create table public.documents (
  id uuid primary key default extensions.uuid_generate_v4(),
  user_id uuid not null references auth.users(id),
  title varchar(40) not null,
  status public.doc_status not null,
  kind text not null check (kind in ('pdf', 'note')),
  embedding extensions.vector(3)
);

alter table public.documents enable row level security;

create policy "Users read their own documents"
  on public.documents for select to authenticated
  using ((select auth.uid()) = user_id);

create function public.match_documents(query extensions.vector(3))
returns setof public.documents
language sql stable
as $$
  select * from public.documents order by embedding <=> query limit 5;
$$;
`;

describe("apps that use Postgres extensions", () => {
  it("loads uuid-ossp and pgvector, skips only what is unavailable, and still tests access", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vibesecure-ext-"));
    mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(dir, "supabase", "migrations", "20260101000000_docs.sql"), MIGRATION);

    const scan = await scanProject(dir);
    try {
      expect(scan.project.load.extensions).toEqual(["uuid-ossp", "vector"]);
      expect(scan.project.load.skipped.map((s) => s.statement)).toEqual(["create extension if not exists pg_net"]);

      const docs = scan.results.find((r) => r.target.key === "public.documents")!;
      expect(docs.tested).toBe(true);
      expect(letters(docs.access.anon)).toBe("····");
      expect(letters(docs.access.other)).toBe("····");
      expect(letters(docs.access.owner)).toBe("R···");
      expect(scan.findings).toEqual([]);
    } finally {
      await scan.project.db.close();
    }
  });
});
