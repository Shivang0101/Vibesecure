import { readdirSync, readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { guardFixSql } from "../src/fix/guard.js";
import type { Intent } from "../src/fix/intent.js";
import { writeMigration } from "../src/fix/migration.js";
import { fixWithTemplate } from "../src/fix/session.js";
import { findLeakyPolicies, templateSql } from "../src/fix/templates.js";
import { verifyFix } from "../src/fix/verify.js";
import { scanProject, type ScanResult } from "../src/scan/index.js";
import { ScriptedHuman } from "../src/ui/human.js";
import { copyOfExampleApp } from "./helpers.js";

let scan: ScanResult;
let projectDir: string;

beforeAll(async () => {
  projectDir = copyOfExampleApp();
  scan = await scanProject(projectDir);
});

afterAll(async () => {
  await scan.project.db.close();
});

const target = (key: string) => scan.project.targets.find((t) => t.key === key)!;
const OWNER_ONLY: Intent = { read: "owner", write: "owner" };

describe("finding the leaky policies", () => {
  it("blames only the policy that lets everyone in", async () => {
    const { leaky, kept } = await findLeakyPolicies(scan.project, target("public.notes"), OWNER_ONLY);
    expect(leaky.map((p) => p.name)).toEqual(["Enable all access"]);
    expect(kept).toEqual([]);
  });

  it("keeps a safe read policy and blames the unchecked insert", async () => {
    const intent: Intent = { read: "signed_in", write: "owner" };
    const { leaky, kept } = await findLeakyPolicies(scan.project, target("public.comments"), intent);
    expect(leaky.map((p) => p.name)).toEqual(["Signed-in users can comment"]);
    expect(kept.map((p) => p.name)).toEqual(["Admins can delete any comment", "Comments are visible to signed-in users"]);
  });

  it("only looks at the policies of the bucket being fixed", async () => {
    const { leaky, kept } = await findLeakyPolicies(scan.project, target("storage:invoices"), OWNER_ONLY);
    expect(leaky.map((p) => p.name)).toEqual(["Signed-in users can read invoices"]);
    expect(kept.map((p) => p.name)).toEqual(["Users upload their own invoices"]);
  });
});

describe("template fixes pass verification", () => {
  const cases: [string, Intent][] = [
    ["public.posts", OWNER_ONLY],
    ["public.notes", OWNER_ONLY],
    ["public.comments", { read: "signed_in", write: "owner" }],
    ["public.author_stats", { read: "owner", write: "nobody" }],
    ["storage:invoices", OWNER_ONLY],
  ];
  for (const [key, intent] of cases) {
    it(`fixes ${key}`, async () => {
      const t = target(key);
      const { leaky } = await findLeakyPolicies(scan.project, t, intent);
      const verification = await verifyFix(scan.project, scan.results, t, intent, templateSql(t, intent, leaky));
      expect(verification.problems).toEqual([]);
      expect(verification.sideEffects).toEqual([]);
      expect(verification.checks.filter((c) => !c.ok)).toEqual([]);
      expect(verification.ok).toBe(true);
    });
  }
});

describe("the verifier", () => {
  it("rejects a fix that still leaks", async () => {
    const sql = `
      alter table public.posts enable row level security;
      create policy "readable by all" on public.posts for select using (true);
    `;
    const verification = await verifyFix(scan.project, scan.results, target("public.posts"), OWNER_ONLY, sql);
    expect(verification.ok).toBe(false);
    expect(verification.checks.find((c) => !c.ok && c.level === "error")?.label).toContain("can't read");
  });

  it("notices when a fix changes access somewhere else", async () => {
    // Every bucket shares storage.objects, so a policy change for one bucket
    // can quietly break another. Here an "avatars" fix drops the invoices upload policy.
    const sql = `drop policy "Users upload their own invoices" on storage.objects;`;
    const intent: Intent = { read: "anyone", write: "owner" };
    const verification = await verifyFix(scan.project, scan.results, target("storage:avatars"), intent, sql);
    expect(verification.ok).toBe(false);
    expect(verification.sideEffects).toEqual(["invoices: the owner can no longer add rows"]);
  });

  it("reports SQL that fails to run", async () => {
    const sql = `create policy "x" on public.posts for select using (no_such_column = 1);`;
    const verification = await verifyFix(scan.project, scan.results, target("public.posts"), OWNER_ONLY, sql);
    expect(verification.ok).toBe(false);
    expect(verification.problems[0]).toContain("failed to run");
  });
});

describe("guardFixSql", () => {
  const posts = () => target("public.posts");

  it("allows RLS, policy, grant and view-security changes", () => {
    const sql = `
      alter table public.posts enable row level security;
      drop policy if exists "old" on public.posts;
      create policy "Owners can read their posts" on "public"."posts" for select using ((select auth.uid()) = user_id);
      alter policy "Owners can read their posts" on public.posts rename to "Owners read posts";
      revoke all on public.posts from anon;
      grant select, insert on table posts to authenticated;
      comment on policy "Owners read posts" on public.posts is 'only the owner';
    `;
    expect(guardFixSql(sql, posts())).toEqual([]);
  });

  it("refuses destructive or unrelated statements", () => {
    for (const sql of [
      "drop table public.posts",
      "delete from public.posts",
      "alter table public.posts disable row level security",
      "grant all on public.posts to public",
      "create function public.f() returns int language sql as $$ select 1 $$",
      "alter table public.posts drop column body",
    ]) {
      expect(guardFixSql(sql, posts()), sql).not.toEqual([]);
    }
  });

  it("refuses changes to other tables", () => {
    expect(guardFixSql("alter table public.notes enable row level security", posts())[0]).toContain("may only change");
  });
});

describe("saving fixes", () => {
  it("names the migration after the newest one and never overwrites", () => {
    const dir = scan.project.load.migrationsDir;
    const first = writeMigration(dir, "posts", "select 1;", new Date("2020-01-01T00:00:00Z"));
    const second = writeMigration(dir, "posts", "select 2;", new Date("2020-01-01T00:00:00Z"));
    expect(first).toMatch(/20260915120001_vibesecure_fix_posts\.sql$/);
    expect(second).toMatch(/20260915120002_vibesecure_fix_posts\.sql$/);
  });

  it("runs the whole template flow with scripted answers", async () => {
    const human = new ScriptedHuman(["owner", "owner", "yes"]);
    const result = await fixWithTemplate(scan, target("public.notes"), human);
    expect(result.status).toBe("saved");
    const saved = readFileSync(result.file!, "utf8");
    expect(saved).toContain('drop policy if exists "Enable all access" on "public"."notes";');
    expect(saved).toContain("(select auth.uid()) = \"user_id\"");
    expect(readdirSync(scan.project.load.migrationsDir).some((f) => f.endsWith("_vibesecure_fix_notes.sql"))).toBe(true);
  });
});
