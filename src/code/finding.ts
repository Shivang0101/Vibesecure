import type { Finding, Severity } from "../scan/findings.js";
import { maskSecrets } from "./patterns.js";
import { isIgnored, lineOf, lineText, type SourceFile } from "./source.js";

export interface CodeIssue {
  rule: string;
  severity: Severity;
  title: string;
  detail?: string;
  fix: string;
  owasp: string;
}

/**
 * A finding at a position in a file, or null when the line carries a
 * `vibesecure-ignore` comment.
 */
export function codeFinding(file: SourceFile, index: number, issue: CodeIssue): Finding | null {
  const line = lineOf(file, index);
  if (isIgnored(file, line)) return null;
  const snippet = showLine(file, line);
  return {
    severity: issue.severity,
    targetKey: `code:${issue.rule}:${file.path}:${line}`,
    label: `${file.path}:${line}`,
    title: issue.title,
    detail: issue.detail,
    fix: issue.fix,
    rule: issue.rule,
    owasp: issue.owasp,
    location: { file: file.path, line },
    snippet: snippet.length > 160 ? `${snippet.slice(0, 157)}...` : snippet,
  };
}

/** The line for the report, without any secret on it. */
function showLine(file: SourceFile, line: number): string {
  const text = lineText(file, line).trim();
  // .env values are never shown, only the variable name.
  return file.kind === "env" ? text.replace(/=.*$/, "=…") : maskSecrets(text);
}

/** Every match of a global regex, with its position. */
export function* matches(text: string, pattern: RegExp): Generator<RegExpExecArray> {
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    yield m;
    if (m[0].length === 0) re.lastIndex++;
  }
}

/**
 * Reads a JS expression starting at `start` until the bracket depth drops
 * below zero or a top-level terminator (`,` `;` or a newline) is reached.
 */
export function readExpression(text: string, start: number, stopAtComma = true): string {
  let depth = 0;
  let quote: string | null = null;
  let k = start;
  for (; k < text.length; k++) {
    const c = text[k]!;
    if (quote) {
      if (c === "\\") k++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) {
      if (depth === 0) break;
      depth--;
    } else if (depth === 0 && (c === ";" || c === "\n" || (stopAtComma && c === ","))) break;
  }
  return text.slice(start, k).trim();
}

/** A plain string literal with nothing interpolated, like "hello" or `hi`. */
export function isLiteral(expr: string): boolean {
  return /^(['"])(?:(?!\1)[^\\]|\\.)*\1$/.test(expr) || /^`[^`$]*`$/.test(expr);
}

/** Wrapped in a known HTML sanitizer. */
export function isSanitized(expr: string): boolean {
  return /sanitize|purify|DOMPurify|escapeHtml|escapeHTML|xss\(/.test(expr);
}
