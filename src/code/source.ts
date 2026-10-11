import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";

/**
 * client: ships to the browser, so anything in it is public.
 * server: runs on a server (edge functions, API routes, server functions).
 * env:    .env files.
 * config: JSON, TOML and YAML files.
 * test:   tests and their helpers, which never ship (only checked for secrets).
 */
export type FileKind = "client" | "server" | "env" | "config" | "test" | "other";

export interface SourceFile {
  /** Path relative to the project, with forward slashes. */
  path: string;
  kind: FileKind;
  /** The file as written. */
  text: string;
  /** Same length and lines as `text`, with comments blanked out. */
  code: string;
  /** Like `code`, with the insides of strings blanked out too. */
  bare: string;
  /** For Supabase edge functions: the function's folder name. */
  functionName?: string;
  lineStarts: number[];
}

const SKIP_DIRS = new Set([
  "node_modules", "dist", "build", "out", "coverage", "vendor", "migrations",
]);
const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"]);
const CONFIG_EXTENSIONS = new Set([".json", ".toml", ".yaml", ".yml"]);
const SKIP_FILES = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "deno.lock"]);
const MAX_BYTES = 1_000_000;

/** Reads every source, config and .env file in the project. */
export function collectFiles(projectDir: string): SourceFile[] {
  const isNext = ["next.config.js", "next.config.mjs", "next.config.ts"].some((f) => existsSync(join(projectDir, f)));
  const files: SourceFile[] = [];
  for (const absolute of walk(projectDir)) {
    const path = relative(projectDir, absolute).split("\\").join("/");
    const text = readFileSync(absolute, "utf8");
    const kind = classify(path, text, isNext);
    const isCode = CODE_EXTENSIONS.has(extname(path)) || path.endsWith(".html");
    const { code, bare } = isCode ? blankJs(text) : { code: text, bare: text };
    const fn = /(?:^|\/)supabase\/functions\/([^/_][^/]*)\//.exec(path)?.[1];
    files.push({ path, kind, text, code, bare, functionName: fn, lineStarts: lineStarts(text) });
  }
  return files;
}

function* walk(dir: string): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries.sort()) {
    const path = join(dir, entry);
    let stats;
    try {
      stats = statSync(path);
    } catch {
      continue;
    }
    if (stats.isDirectory()) {
      if (!entry.startsWith(".") && !SKIP_DIRS.has(entry)) yield* walk(path);
    } else if (stats.size <= MAX_BYTES && wanted(entry)) {
      yield path;
    }
  }
}

function wanted(name: string): boolean {
  if (SKIP_FILES.has(name)) return false;
  if (name.startsWith(".env")) return true;
  const ext = extname(name);
  return CODE_EXTENSIONS.has(ext) || CONFIG_EXTENSIONS.has(ext) || name === "index.html";
}

function classify(path: string, text: string, isNext: boolean): FileKind {
  const name = basename(path);
  if (name.startsWith(".env")) return "env";
  if (CONFIG_EXTENSIONS.has(extname(path))) return "config";
  if (!CODE_EXTENSIONS.has(extname(path)) && name !== "index.html") return "other";
  if (isTestFile(path)) return "test";
  if (isServerFile(path, text)) return "server";
  if (isClientFile(path, text, isNext)) return "client";
  return "other";
}

function isTestFile(path: string): boolean {
  return (
    /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|cypress|playwright)\//.test(path) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/.test(path)
  );
}

/** Code that runs on a server: edge functions, API routes, server functions. */
function isServerFile(path: string, text: string): boolean {
  if (/(^|\/)(supabase\/functions|netlify\/functions)\//.test(path) || /^functions\//.test(path)) return true;
  if (/(^|\/)(api|server)\//.test(path)) return true;
  if (/(^|\/)app\/.*\/route\.(ts|js)$/.test(path)) return true;
  return /createServerFn\s*\(|["']use server["']|createServerFileRoute|createAPIFileRoute/.test(text);
}

/**
 * Code that ships to the browser. In a Vite app (Lovable, Bolt) that's all of
 * src/. In a Next.js app only "use client" files and components are bundled.
 */
function isClientFile(path: string, text: string, isNext: boolean): boolean {
  if (path === "index.html" || path.startsWith("public/")) return true;
  if (isNext) {
    return /["']use client["']/.test(text) || /^(src\/)?(components|hooks)\//.test(path) || /^(src\/)?pages\//.test(path);
  }
  return /^(src|app|components|pages|lib|hooks)\//.test(path);
}

/**
 * Returns two copies of a JS/TS file with the same length and line breaks:
 *  - code: comments blanked, so commented-out code doesn't count
 *  - bare: comments and string contents blanked, so "does the code use X?"
 *    checks don't match error messages like "Rate limit exceeded"
 */
export function blankJs(text: string): { code: string; bare: string } {
  const code = text.split("");
  const bare = text.split("");
  const blank = (chars: string[], from: number, to: number) => {
    for (let k = from; k < to; k++) if (chars[k] !== "\n") chars[k] = " ";
  };

  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    const next = text[i + 1];
    if (ch === "/" && next === "/") {
      const end = text.indexOf("\n", i);
      const stop = end === -1 ? text.length : end;
      blank(code, i, stop);
      blank(bare, i, stop);
      i = stop;
    } else if (ch === "/" && next === "*") {
      const end = text.indexOf("*/", i + 2);
      const stop = end === -1 ? text.length : end + 2;
      blank(code, i, stop);
      blank(bare, i, stop);
      i = stop;
    } else if (ch === "/" && startsRegex(text, i)) {
      i = skipRegex(text, i);
    } else if (ch === "'" || ch === '"' || ch === "`") {
      const stop = skipString(text, i, ch);
      blank(bare, i + 1, Math.max(i + 1, stop - 1));
      i = stop;
    } else {
      i++;
    }
  }
  return { code: code.join(""), bare: bare.join("") };
}

function skipString(text: string, start: number, quote: string): number {
  let k = start + 1;
  while (k < text.length) {
    const c = text[k];
    if (c === "\\") {
      k += 2;
    } else if (c === quote) {
      return k + 1;
    } else if (quote !== "`" && c === "\n") {
      return k; // an apostrophe in JSX text, not a real string
    } else {
      k++;
    }
  }
  return text.length;
}

/** A `/` starts a regex literal when it follows an operator or bracket, not a value. */
function startsRegex(text: string, i: number): boolean {
  let k = i - 1;
  while (k >= 0 && (text[k] === " " || text[k] === "\t")) k--;
  if (k < 0) return true;
  return "(,=:[!&|?{};+-*%<>~^\n".includes(text[k]!) || /\breturn$/.test(text.slice(Math.max(0, k - 6), k + 1));
}

function skipRegex(text: string, start: number): number {
  let k = start + 1;
  let inClass = false;
  while (k < text.length && text[k] !== "\n") {
    const c = text[k];
    if (c === "\\") {
      k += 2;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) return k + 1;
    k++;
  }
  return k;
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}

/** 1-based line number of a character position. */
export function lineOf(file: SourceFile, index: number): number {
  let low = 0;
  let high = file.lineStarts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (file.lineStarts[mid]! <= index) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

export function lineText(file: SourceFile, line: number): string {
  const start = file.lineStarts[line - 1] ?? 0;
  const end = file.lineStarts[line] ?? file.text.length;
  return file.text.slice(start, end).replace(/\r?\n$/, "");
}

/** `// vibesecure-ignore` on the line or the line above silences a finding. */
export function isIgnored(file: SourceFile, line: number): boolean {
  return [line, line - 1].some((l) => l >= 1 && lineText(file, l).includes("vibesecure-ignore"));
}
