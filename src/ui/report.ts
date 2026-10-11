import pc from "picocolors";
import { SEVERITY_ORDER, type Finding, type Severity } from "../scan/findings.js";
import type { AccessResult, AccessRow, Operation } from "../scan/matrix.js";
import type { ScanResult } from "../scan/index.js";

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
  lines.push("");
  lines.push(renderMatrix(scan.results));
  lines.push("");

  if (scan.findings.length === 0) {
    lines.push(pc.green("No problems found. Other users and strangers can't reach anyone's data."));
  } else {
    lines.push(pc.bold("What we found"));
    for (const finding of scan.findings) lines.push(renderFinding(finding));
  }

  if (load.skipped.length > 0) {
    lines.push("");
    lines.push(pc.dim("Skipped statements (features this offline copy doesn't have):"));
    for (const s of load.skipped.slice(0, 8)) lines.push(pc.dim(`  ${s.file}: ${s.statement} (${s.error})`));
    if (load.skipped.length > 8) lines.push(pc.dim(`  ...and ${load.skipped.length - 8} more`));
  }
  return lines.join("\n");
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
  const detail = finding.detail ? `\n${" ".repeat(11)}${pc.dim(finding.detail)}` : "";
  return `  ${tag}${finding.title}${detail}`;
}

/** Highest severity found, or null. */
export function worstSeverity(findings: Finding[]): Severity | null {
  for (const level of SEVERITY_ORDER) if (findings.some((f) => f.severity === level)) return level;
  return null;
}

/** A plain object for --json output. */
export function scanToJson(scan: ScanResult) {
  return {
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
    findings: scan.findings,
  };
}
