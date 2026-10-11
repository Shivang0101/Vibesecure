import type { AccessResult, AccessRow, Operation } from "./matrix.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  severity: Severity;
  /**
   * What this is about: "public.posts" for a table, "column:public.profiles.role"
   * for a column, "function:public.f" for a database function, or
   * "code:<rule>:<file>:<line>" for a problem in the app's source.
   */
  targetKey: string;
  label: string;
  title: string;
  detail?: string;
  /** How to fix it, in a sentence or two. */
  fix?: string;
  /** Stable id of the check that found it, e.g. "xss-dangerous-html". */
  rule?: string;
  /** OWASP Top 10 (2021) category, e.g. "A03 Injection". */
  owasp?: string;
  /** Where in the source, for code findings. */
  location?: { file: string; line: number };
  /** The line of code, for code findings. */
  snippet?: string;
  /** Marks findings that get special handling (merging, or their own fix). */
  code?: "no_api_grants" | "privilege_escalation";
}

/** OWASP Top 10 (2021) categories the checks map to. */
export const OWASP = {
  accessControl: "A01 Broken Access Control",
  crypto: "A02 Cryptographic Failures",
  injection: "A03 Injection",
  insecureDesign: "A04 Insecure Design",
  misconfiguration: "A05 Security Misconfiguration",
  authentication: "A07 Identification and Authentication Failures",
  integrity: "A08 Software and Data Integrity Failures",
  ssrf: "A10 Server-Side Request Forgery",
} as const;

/** Column names that suggest personal or secret data. */
const SENSITIVE = /(email|phone|address|password|secret|token|api_?key|ssn|birth|dob|salary|iban|card|passport|diagnos|medical|health)/i;

/**
 * Turns the measured access into plain-English findings: one sentence for
 * what strangers can do and one for what other signed-in users can do.
 * We can't know the intent yet (maybe posts *are* public), so reads alone are
 * worded as facts with a hint; anyone changing other people's data is critical.
 */
export function deriveFindings(results: AccessResult[]): Finding[] {
  return sortFindings(mergeNoGrants(results.flatMap(findingsFor)));
}

/** Worst first. The sort is stable, so findings of equal severity keep their order. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

/** One line for all tables without API grants, instead of the same note per table. */
function mergeNoGrants(findings: Finding[]): Finding[] {
  const noGrants = findings.filter((f) => f.code === "no_api_grants");
  if (noGrants.length <= 1) return findings;
  const labels = noGrants.map((f) => f.label);
  const merged: Finding = {
    ...noGrants[0]!,
    label: labels.join(", "),
    title: `${labels.length} tables aren't exposed to the API (no grants), so your app can't use them: ${labels.join(", ")}.`,
  };
  return [...findings.filter((f) => f.code !== "no_api_grants"), merged];
}

function findingsFor(result: AccessResult): Finding[] {
  const { target, access } = result;
  const out: Finding[] = [];
  const add = (severity: Severity, title: string, ...details: (string | undefined)[]) => {
    const detail = details.filter(Boolean).join(" ");
    out.push({
      severity,
      targetKey: target.key,
      label: target.label,
      title,
      detail: detail || undefined,
      rule: "db-access",
      owasp: OWASP.accessControl,
    });
    return out[out.length - 1]!;
  };

  const rlsOff = target.kind === "table" && !target.relation.rlsEnabled;
  const rlsNote = rlsOff ? "RLS is turned off for this table." : undefined;

  if (!result.tested) {
    if (rlsOff) {
      add("high", `${target.label} has RLS turned off, so anyone with your public API key can read and change it.`, result.note);
    } else {
      add("info", `Couldn't test ${target.label}.`, result.note);
    }
    return out;
  }

  if (target.kind === "view") {
    const bypass = target.relation.securityInvoker
      ? undefined
      : "Views run with their creator's rights unless created with security_invoker = on, so they skip the RLS of the tables they read.";
    if (target.ownerColumn && access.anon.read?.allowed) {
      add("high", `Anyone on the internet can read every user's rows through the ${target.label} view.`, bypass, sensitiveNote(result));
    } else if (target.ownerColumn && access.other.read?.allowed) {
      add("medium", `Any signed-in user can read other users' rows through the ${target.label} view.`, bypass);
    } else if (!target.ownerColumn && access.anon.read?.allowed && !target.relation.securityInvoker) {
      add("medium", `The ${target.label} view shows all of its rows to anyone on the internet.`, bypass);
    }
    return out;
  }

  const anonOps = allowedOps(access.anon);
  // Only mention what signed-in users can do *beyond* what strangers already can.
  const otherOps = allowedOps(access.other).filter((op) => !anonOps.includes(op));

  if (target.kind === "bucket") {
    const where = `in the "${target.label}" bucket`;
    if (target.bucket?.public) {
      add("info", `Files ${where} are public: anyone with a file's link can download it.`);
    }
    // In a public bucket, strangers reading files is the point; the note above covers it.
    const anonShown = target.bucket?.public ? anonOps.filter((op) => op !== "read") : anonOps;
    if (anonShown.length > 0) {
      add(severityFor(anonShown, "anon", true), `Anyone on the internet can ${fileVerbs(anonShown)} ${where}.`);
    }
    if (otherOps.length > 0) {
      add(severityFor(otherOps, "other", true), `Any signed-in user can ${fileVerbs(otherOps)} ${where}.`);
    }
    return out;
  }

  // Tables.
  const { grants } = target.relation;
  if (grants.anon.length === 0 && grants.authenticated.length === 0) {
    add(
      "info",
      `${target.label} isn't exposed to the API (no grants), so your app can't read or write it.`,
      "Since Oct 30, 2026 Supabase no longer grants new tables to the API automatically. " +
        "If your app needs a table, add a grant for the authenticated role (with RLS on).",
    ).code = "no_api_grants";
    return out;
  }

  const owned = target.ownerColumn !== null;
  if (owned) {
    if (anonOps.length > 0) {
      const readOnly = anonOps.length === 1 && anonOps[0] === "read";
      add(
        severityFor(anonOps, "anon", true),
        `Anyone on the internet can ${rowVerbs(anonOps, target.label)}.`,
        rlsNote,
        sensitiveNote(result),
        readOnly ? `Fine only if ${target.label} is meant to be public, like published blog posts.` : undefined,
      );
    }
    if (otherOps.length > 0) {
      add(
        severityFor(otherOps, "other", true),
        `Any signed-in user can ${rowVerbs(otherOps, target.label)}.`,
        otherOps.includes("insert")
          ? "The insert policy doesn't check that the owner column matches auth.uid()."
          : undefined,
      );
    }
  } else {
    // Without an owner column every row is shared, so we only flag what is
    // almost never intended: strangers writing, or anyone deleting everything.
    const anonWrites = anonOps.filter((op) => op !== "read");
    if (anonWrites.length > 0) {
      add(
        severityFor(anonWrites, "anon", false),
        `Anyone on the internet can ${sharedVerbs(anonWrites, target.label)}.`,
        rlsNote,
        anonWrites.length === 1 && anonWrites[0] === "insert"
          ? "If that's on purpose (a contact form or waitlist), add a captcha or rate limit: the API has none, so bots can fill it with junk."
          : undefined,
      );
    }
    const otherWrites = otherOps.filter((op) => op === "update" || op === "delete");
    if (otherWrites.length > 0) {
      add("high", `Any signed-in user can ${sharedVerbs(otherWrites, target.label)}.`, rlsNote);
    }
    if (anonOps.includes("read")) {
      const sensitive = sensitiveNote(result);
      add(
        sensitive ? "high" : "low",
        `Anyone on the internet can read all rows in ${target.label}.`,
        sensitive ?? "Fine for public data like categories or prices.",
      );
    }
  }
  return out;
}

function allowedOps(row: AccessRow): Operation[] {
  return (["read", "insert", "update", "delete"] as Operation[]).filter((op) => row[op]?.allowed);
}

function severityFor(ops: Operation[], who: "anon" | "other", owned: boolean): Severity {
  if (ops.includes("update") || ops.includes("delete")) return owned ? "critical" : who === "anon" ? "critical" : "high";
  if (ops.includes("insert")) return "high";
  return who === "anon" ? "high" : "medium";
}

/** "read, edit and delete other users' rows in posts, and add rows in their name" */
function rowVerbs(ops: Operation[], label: string): string {
  const verbs = [ops.includes("read") && "read", ops.includes("update") && "edit", ops.includes("delete") && "delete"]
    .filter((v): v is string => Boolean(v));
  const main = verbs.length > 0 ? `${joinWords(verbs)} other users' rows in ${label}` : "";
  const add = ops.includes("insert") ? `add rows to ${label} in other users' names` : "";
  return main && add ? `${main}, and ${add}` : main || add;
}

/** "add, edit and delete rows in categories" */
function sharedVerbs(ops: Operation[], label: string): string {
  const verbs = [ops.includes("insert") && "add", ops.includes("update") && "edit", ops.includes("delete") && "delete"]
    .filter((v): v is string => Boolean(v));
  return `${joinWords(verbs)} rows in ${label}`;
}

/** "list and read, overwrite and delete other users' files" */
function fileVerbs(ops: Operation[]): string {
  const verbs = [
    ops.includes("read") && "list and read",
    ops.includes("update") && "overwrite",
    ops.includes("delete") && "delete",
  ].filter((v): v is string => Boolean(v));
  const main = verbs.length > 0 ? `${joinWords(verbs)} other users' files` : "";
  const add = ops.includes("insert") ? "upload files into other users' folders" : "";
  return main && add ? `${main}, and ${add}` : main || add;
}

function joinWords(words: string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

function sensitiveNote(result: AccessResult): string | undefined {
  const columns = result.target.relation.columns.map((c) => c.name).filter((c) => SENSITIVE.test(c));
  return columns.length > 0 ? `Columns that look private: ${columns.join(", ")}.` : undefined;
}

/** True when the target has a problem worth fixing (medium or worse). */
export function needsFix(findings: Finding[], targetKey: string): boolean {
  return findings.some(
    (f) => f.targetKey === targetKey && SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf("medium"),
  );
}
