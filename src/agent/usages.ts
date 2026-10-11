import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

export interface CodeUsage {
  file: string;
  line: number;
  /** The matching line plus the next few, which usually hold the chained .select()/.eq() calls. */
  code: string;
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".output", ".vercel", ".netlify",
  "coverage", ".vibesecure", "migrations",
]);
const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"]);
const MAX_FILE_BYTES = 1_000_000;

/**
 * Finds where the app's code talks to a table or bucket through supabase-js,
 * e.g. supabase.from("posts").select("*").eq("user_id", user.id).
 * Seeing that filter is a strong hint the data is meant to be private.
 */
export function findUsages(projectDir: string, name: string, kind: "table" | "view" | "bucket", limit = 20) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const quoted = `['"\`]${escaped}['"\`]`;
  const pattern =
    kind === "bucket"
      ? new RegExp(String.raw`storage\s*\.\s*from\(\s*${quoted}\s*\)`)
      : new RegExp(String.raw`\.from\(\s*${quoted}\s*\)|\.rpc\(\s*${quoted}`);

  const matches: CodeUsage[] = [];
  let total = 0;
  for (const file of codeFiles(projectDir)) {
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((text, index) => {
      if (!pattern.test(text)) return;
      total++;
      if (matches.length >= limit) return;
      matches.push({
        file: relative(projectDir, file),
        line: index + 1,
        code: lines.slice(index, index + 5).map((l) => l.trimEnd()).join("\n"),
      });
    });
  }
  return { matches, total };
}

function* codeFiles(dir: string): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = join(dir, entry);
    let stats;
    try {
      stats = statSync(path);
    } catch {
      continue;
    }
    if (stats.isDirectory()) {
      if (!SKIP_DIRS.has(entry) && !entry.startsWith(".")) yield* codeFiles(path);
    } else if (CODE_EXTENSIONS.has(extname(entry)) && stats.size <= MAX_FILE_BYTES) {
      yield path;
    }
  }
}
