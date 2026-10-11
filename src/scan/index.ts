import type { PGliteInterface } from "@electric-sql/pglite";
import { introspect, type SchemaInfo } from "../db/introspect.js";
import { loadProjectDatabase, type LoadReport } from "../db/load.js";
import { deriveFindings, type Finding } from "./findings.js";
import { measureAccess, type AccessResult } from "./matrix.js";
import { seedDatabase, type SeedReport } from "./seed.js";
import { buildTargets, type Target } from "./targets.js";

export interface ScanOptions {
  /** Schemas the Supabase API exposes. Supabase exposes `public` by default. */
  schemas?: string[];
  /** Simulate Supabase's old default of granting new tables to the API roles. */
  defaultGrants?: boolean;
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
  findings: Finding[];
}

export async function prepareProject(projectDir: string, options: ScanOptions = {}): Promise<PreparedProject> {
  const resolved: Required<ScanOptions> = {
    schemas: options.schemas ?? ["public"],
    defaultGrants: options.defaultGrants ?? true,
  };
  const { db, report } = await loadProjectDatabase(projectDir, { defaultGrants: resolved.defaultGrants });
  const schema = await introspect(db, resolved.schemas);
  const targets = buildTargets(schema);
  const seed = await seedDatabase(db, targets);
  return { projectDir, db, load: report, schema, targets, seed, options: resolved };
}

export async function scanPrepared(project: PreparedProject): Promise<ScanResult> {
  const results = await measureAccess(project.db, project.targets, project.seed);
  return { project, results, findings: deriveFindings(results) };
}

/** Load the migrations, create test users and rows, and test who can do what. */
export async function scanProject(projectDir: string, options: ScanOptions = {}): Promise<ScanResult> {
  return scanPrepared(await prepareProject(projectDir, options));
}
