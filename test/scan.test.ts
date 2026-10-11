import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { scanProject, type ScanResult } from "../src/scan/index.js";
import { EXAMPLE_APP, letters } from "./helpers.js";

let scan: ScanResult;

beforeAll(async () => {
  scan = await scanProject(EXAMPLE_APP);
});

afterAll(async () => {
  await scan.project.db.close();
});

function access(key: string) {
  const result = scan.results.find((r) => r.target.key === key);
  if (!result) throw new Error(`no target ${key}`);
  return {
    anon: letters(result.access.anon),
    other: letters(result.access.other),
    owner: letters(result.access.owner),
  };
}

describe("scan of the leaky example app", () => {
  it("loads every migration and skips only what PGlite can't run", () => {
    expect(scan.project.load.files).toHaveLength(4);
    expect(scan.project.load.skipped.map((s) => s.statement)).toEqual([
      "create extension if not exists pg_cron",
      expect.stringContaining("cron.schedule"),
    ]);
  });

  it("finds owner columns", () => {
    const owner = (key: string) => scan.project.targets.find((t) => t.key === key)?.ownerColumn;
    expect(owner("public.posts")).toBe("user_id");
    expect(owner("public.profiles")).toBe("id");
    expect(owner("public.comments")).toBe("author_id");
    expect(owner("public.categories")).toBeNull();
    expect(owner("public.author_stats")).toBe("user_id");
  });

  it("measures the open tables as open", () => {
    expect(access("public.posts")).toEqual({ anon: "RAED", other: "RAED", owner: "RAED" });
    expect(access("public.notes")).toEqual({ anon: "RAED", other: "RAED", owner: "RAED" });
  });

  it("measures the protected tables as protected", () => {
    expect(access("public.todos")).toEqual({ anon: "····", other: "····", owner: "RAED" });
    expect(access("public.profiles")).toEqual({ anon: "····", other: "····", owner: "R·E·" });
  });

  it("catches an insert policy that doesn't check the author", () => {
    expect(access("public.comments").other).toBe("RA··");
  });

  it("catches a view that skips RLS", () => {
    expect(access("public.author_stats")).toEqual({ anon: "R", other: "R", owner: "R" });
  });

  it("tests storage buckets per bucket", () => {
    expect(access("storage:avatars")).toEqual({ anon: "R···", other: "R···", owner: "RA··" });
    expect(access("storage:invoices")).toEqual({ anon: "····", other: "R···", owner: "RA··" });
  });

  it("reports database findings in plain English, worst first", () => {
    const database = scan.findings.filter((f) => !f.location);
    expect(database.map((f) => [f.severity, f.label])).toEqual([
      ["critical", "notes"],
      ["critical", "posts"],
      ["critical", "profiles.role"],
      ["critical", "search_posts()"],
      ["high", "author_stats"],
      ["high", "comments"],
      ["high", "delete_user_notes()"],
      ["medium", "invoices"],
      ["low", "categories"],
      ["info", "avatars"],
    ]);
    expect(database[1]!.detail).toContain("RLS is turned off");
  });

  it("puts code findings after the database ones, with file and line", () => {
    const firstCode = scan.findings.findIndex((f) => f.location);
    expect(firstCode).toBeGreaterThan(0);
    const code = scan.findings.filter((f) => f.location);
    expect(code.every((f) => f.rule && f.owasp && f.fix)).toBe(true);
    expect(code.map((f) => f.label)).toContain("src/components/CommentBody.tsx:5");
  });
});

describe("with Supabase's newer default of no automatic grants", () => {
  it("reports tables the API can't reach instead of leaks", async () => {
    const strict = await scanProject(EXAMPLE_APP, { defaultGrants: false });
    try {
      const noGrants = strict.findings.filter((f) => f.code === "no_api_grants");
      expect(noGrants).toHaveLength(1);
      expect(noGrants[0]!.title).toContain("6 tables aren't exposed to the API");
      const tableLeaks = strict.findings.filter((f) => f.rule === "db-access" || f.rule === "db-privilege-escalation");
      expect(tableLeaks.some((f) => f.severity === "critical")).toBe(false);
      // Postgres lets everyone execute new functions, grants or not.
      expect(strict.findings.some((f) => f.label === "search_posts()")).toBe(true);
    } finally {
      await strict.project.db.close();
    }
  });
});
