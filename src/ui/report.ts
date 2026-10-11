import pc from "picocolors";
import { SEVERITY_ORDER, type Finding, type Severity } from "../scan/findings.js";
import type { AccessResult, AccessRow, Operation } from "../scan/matrix.js";
import type { CodeOnlyResult, ScanResult } from "../scan/index.js";

const LETTER: Record<Operation, string> = { read: "R", insert: "A", update: "E", delete: "D" };

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bold(pc.red(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.dim,
};

/** The full scan report for the terminal. */
export function renderScan(scan: ScanResult, projectLabel: string): string {
  const { load } = scan.project;
  const lines: string[] = [];

  lines.push(pc.bold(`Vibesecure scan · ${projectLabel}`));
  lines.push(
    pc.dim(
      `Loaded ${load.files.length} migration${load.files.length === 1 ? "" : "s"} ` +
        `(${load.statementCount} statements${load.skipped.length > 0 ? `, ${load.skipped.length} skipped` : ""}) ` +
        "into an in-memory Postgres. Your real database was not touched.",
    ),
  );
  if (scan.code) lines.push(pc.dim(codeLine(scan.code.files)));
  lines.push("");
  lines.push(renderMatrix(scan.results));
  lines.push("");

  if (scan.findings.length === 0) {
    lines.push(pc.green("No problems found. Other users and strangers can't reach anyone's data."));
  } else {
    lines.push(...renderFindings(scan.findings));
  }

  if (load.skipped.length > 0) {
    lines.push("");
    lines.push(pc.dim("Skipped statements (features this offline copy doesn't have):"));
    for (const s of load.skipped.slice(0, 8)) lines.push(pc.dim(`  ${s.file}: ${s.statement} (${s.error})`));
    if (load.skipped.length > 8) lines.push(pc.dim(`  ...and ${load.skipped.length - 8} more`));
  }
  return lines.join("\n");
}

/** The report for a project without Supabase migrations: code checks only. */
export function renderCodeOnly(result: CodeOnlyResult, projectLabel: string): string {
  const lines = [
    pc.bold(`Vibesecure scan · ${projectLabel}`),
    pc.dim("No Supabase migrations found (supabase/migrations/*.sql), so only the code was checked."),
    pc.dim(codeLine(result.code.files)),
    "",
  ];
  if (result.findings.length === 0) {
    lines.push(pc.green("No problems found in the code."));
  } else {
    lines.push(...renderFindings(result.findings));
  }
  return lines.join("\n");
}

function codeLine(files: number): string {
  return `Checked ${files} file${files === 1 ? "" : "s"} of app code for XSS, leaked keys, open endpoints, injection and more.`;
}

/** Database problems first, then code problems with their file and line, then a count. */
function renderFindings(findings: Finding[]): string[] {
  const lines: string[] = [];
  const database = findings.filter((f) => !f.location);
  const code = findings.filter((f) => f.location);
  if (database.length > 0) {
    lines.push(pc.bold("Database"));
    for (const finding of database) lines.push(renderFinding(finding));
  }
  if (code.length > 0) {
    if (database.length > 0) lines.push("");
    lines.push(pc.bold("App code"));
    for (const finding of code) lines.push(renderFinding(finding));
  }
  lines.push("");
  lines.push(summaryLine(findings));
  return lines;
}

/** "2 critical · 5 high · 3 medium" */
function summaryLine(findings: Finding[]): string {
  const parts = SEVERITY_ORDER.map((level) => {
    const count = findings.filter((f) => f.severity === level).length;
    return count > 0 ? SEVERITY_COLOR[level](`${count} ${level}`) : null;
  }).filter((p): p is string => p !== null);
  return `${pc.bold(`${findings.length} finding${findings.length === 1 ? "" : "s"}:`)} ${parts.join(pc.dim(" · "))}`;
}

function renderMatrix(results: AccessResult[]): string {
  const nameWidth = Math.max(12, ...results.map((r) => displayName(r).length)) + 3;
  const title = pc.bold("Who can reach user A's data?");
  const header = "  " + pc.dim("".padEnd(nameWidth) + "strangers".padEnd(12) + "other users".padEnd(14) + "owner");
  const rows = results.map((r) => {
    const name = `  ${displayName(r).padEnd(nameWidth)}`;
    if (!r.tested) return `${name}${pc.yellow("not tested")}`;
    const anon = cells(r, r.access.anon, true);
    const other = cells(r, r.access.other, true);
    return name + anon.padEnd(12 + invisible(anon)) + other.padEnd(14 + invisible(other)) + cells(r, r.access.owner, false);
  });
  const legend = pc.dim("  R read  A add  E edit  D delete  · blocked  ? couldn't tell");
  return [title, header, ...rows, "", legend].join("\n");
}

function displayName(r: AccessResult): string {
  const suffix = r.target.kind === "view" ? " (view)" : r.target.kind === "bucket" ? " (bucket)" : "";
  return `${r.target.label}${suffix}`;
}

/**
 * "R·ED": a letter for each allowed operation. Red means someone other than
 * the owner got into private data; yellow means shared data that is often
 * public on purpose (reading a table with no owner, or a public bucket).
 */
function cells(r: AccessResult, row: AccessRow, isOutsider: boolean): string {
  const ops: Operation[] = r.target.kind === "view" ? ["read"] : ["read", "insert", "update", "delete"];
  return ops
    .map((op) => {
      const result = row[op];
      if (!result) return " ";
      if (result.inconclusive) return pc.yellow("?");
      if (!result.allowed) return pc.dim("·");
      if (!isOutsider) return pc.green(LETTER[op]);
      const oftenPublic = op === "read" && (r.target.ownerColumn === null || r.target.bucket?.public === true);
      return oftenPublic ? pc.yellow(LETTER[op]) : pc.red(LETTER[op]);
    })
    .join("");
}

/** padEnd counts color codes as characters; this is how many to add back. */
function invisible(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.length - s.replace(/\u001b\[[0-9;]*m/g, "").length;
}

function renderFinding(finding: Finding): string {
  const tag = SEVERITY_COLOR[finding.severity](finding.severity.toUpperCase().padEnd(9));
  const indent = " ".repeat(11);
  const lines = [`  ${tag}${finding.title}`];
  const where = finding.location ? `${finding.location.file}:${finding.location.line}` : null;
  // Table access findings are all A01 and the matrix explains them; others get their category.
  const category = finding.rule !== "db-access" ? finding.owasp : undefined;
  if (where || category) lines.push(indent + pc.dim([where, category].filter(Boolean).join(" · ")));
  if (finding.detail) lines.push(indent + pc.dim(finding.detail));
  // Table access problems are what `vibesecure fix` is for; everything else says how to fix it.
  if (finding.fix && finding.rule !== "db-access") lines.push(indent + pc.dim(`Fix: ${finding.fix}`));
  return lines.join("\n");
}

/** Highest severity found, or null. */
export function worstSeverity(findings: Finding[]): Severity | null {
  for (const level of SEVERITY_ORDER) if (findings.some((f) => f.severity === level)) return level;
  return null;
}

/** A plain object for --json output. */
export function scanToJson(scan: ScanResult) {
  return {
    summary: summary(scan.findings),
    migrations: {
      directory: scan.project.load.migrationsDir,
      files: scan.project.load.files,
      statements: scan.project.load.statementCount,
      skipped: scan.project.load.skipped,
    },
    targets: scan.results.map((r) => ({
      key: r.target.key,
      kind: r.target.kind,
      ownerColumn: r.target.ownerColumn,
      rlsEnabled: r.target.kind === "table" ? r.target.relation.rlsEnabled : undefined,
      tested: r.tested,
      note: r.note,
      access: r.access,
    })),
    escalations: scan.escalations.map((e) => ({
      table: e.target.key,
      column: e.column.name,
      value: e.value.text,
      byEditingOwnRow: e.viaUpdate,
      byAddingRow: e.viaInsert,
    })),
    code: scan.code ? { files: scan.code.files } : null,
    findings: scan.findings,
  };
}

export function codeOnlyToJson(result: CodeOnlyResult) {
  return {
    summary: summary(result.findings),
    migrations: null,
    code: { files: result.code.files },
    findings: result.findings,
  };
}

function summary(findings: Finding[]): Record<Severity, number> {
  return Object.fromEntries(SEVERITY_ORDER.map((level) => [level, findings.filter((f) => f.severity === level).length])) as Record<
    Severity,
    number
  >;
}
