import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const EXAMPLE_APP = fileURLToPath(new URL("../examples/leaky-app", import.meta.url));

/** A private copy of the example app, so tests that save migrations don't touch the repo. */
export function copyOfExampleApp(): string {
  const dir = mkdtempSync(join(tmpdir(), "vibesecure-test-"));
  cpSync(EXAMPLE_APP, dir, { recursive: true });
  return dir;
}

/** The access row of a target as a compact string, e.g. "RAED" or "····". */
export function letters(row: Partial<Record<"read" | "insert" | "update" | "delete", { allowed: boolean }>>): string {
  const letter = { read: "R", insert: "A", update: "E", delete: "D" } as const;
  return (["read", "insert", "update", "delete"] as const)
    .map((op) => (row[op] === undefined ? " " : row[op]!.allowed ? letter[op] : "·"))
    .join("")
    .trimEnd();
}

export const ROLES_APP = fileURLToPath(new URL("./fixtures/roles-app", import.meta.url));

/** A private copy of any fixture project. */
export function copyOf(dir: string): string {
  const copy = mkdtempSync(join(tmpdir(), "vibesecure-test-"));
  cpSync(dir, copy, { recursive: true });
  return copy;
}

/** A throwaway project made of the given files, e.g. { "src/App.tsx": "..." }. */
export function makeProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "vibesecure-code-"));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
