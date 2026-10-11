import type { PGliteInterface } from "@electric-sql/pglite";
import { runCodeChecks, type CodeReport } from "../code/index.js";
import { introspect, type SchemaInfo } from "../db/introspect.js";
import { loadProjectDatabase, type LoadReport } from "../db/load.js";
import { passwordColumnFindings } from "./columns.js";
import { escalationFindings, measureEscalation, type Escalation } from "./escalation.js";
import { deriveFindings, sortFindings, type Finding } from "./findings.js";
import { functionFindings, readFunctions, type DatabaseFunction } from "./functions.js";
import { measureAccess, type AccessResult } from "./matrix.js";
import { seedDatabase, type SeedReport } from "./seed.js";
import { buildTargets, type Target } from "./targets.js";

export interface ScanOptions {
  /** Schemas the Supabase API exposes. Supabase exposes `public` by default. */
  schemas?: string[];
  /** Simulate Supabase's old default of granting new tables to the API roles. */
  defaultGrants?: boolean;
  /** Also check the app's source code: XSS, secrets, rate limits and more. */
  code?: boolean;
}

/** A loaded, seeded copy of the project's database, ready for access tests. */
export interface PreparedProject {
  projectDir: string;
  db: PGliteInterface;
  load: LoadReport;
  schema: SchemaInfo;
  targets: Target[];
  seed: SeedReport;
  options: Required<ScanOptions>;
}

export interface ScanResult {
  project: PreparedProject;
  results: AccessResult[];
  /** Columns like `role` that users can set on their own rows. */
  escalations: Escalation[];
  functions: DatabaseFunction[];
  /** The source code checks, or null with `code: false`. */
  code: CodeReport | null;
  findings: Finding[];
}

/** For projects without Supabase migrations: only the source code is checked. */
export interface CodeOnlyResult {
  projectDir: string;
  code: CodeReport;
  findings: Finding[];
}

export async function prepareProject(projectDir: string, options: ScanOptions = {}): Promise<PreparedProject> {
  const resolved: Required<ScanOptions> = {
    schemas: options.schemas ?? ["public"],
    defaultGrants: options.defaultGrants ?? true,
    code: options.code ?? true,
  };
  const { db, report } = await loadProjectDatabase(projectDir, { defaultGrants: resolved.defaultGrants });
  const schema = await introspect(db, resolved.schemas);
  const targets = buildTargets(schema);
  const seed = await seedDatabase(db, targets);
  return { projectDir, db, load: report, schema, targets, seed, options: resolved };
}

export async function scanPrepared(project: PreparedProject): Promise<ScanResult> {
  const results = await measureAccess(project.db, project.targets, project.seed);
  const escalations = await measureEscalation(project.db, project.targets, project.seed);
  const functions = await readFunctions(project.db, project.options.schemas);
  const code = project.options.code ? runCodeChecks(project.projectDir) : null;
  const findings = sortFindings([
    ...deriveFindings(results),
    ...escalationFindings(escalations, project.schema.relations, functions),
    ...functionFindings(functions, project.schema),
    ...passwordColumnFindings(project.schema),
    ...(code?.findings ?? []),
  ]);
  return { project, results, escalations, functions, code, findings };
}

export function scanCodeOnly(projectDir: string): CodeOnlyResult {
  const code = runCodeChecks(projectDir);
  return { projectDir, code, findings: sortFindings(code.findings) };
}

/** Load the migrations, create test users and rows, test who can do what, and check the code. */
export async function scanProject(projectDir: string, options: ScanOptions = {}): Promise<ScanResult> {
  return scanPrepared(await prepareProject(projectDir, options));
}
