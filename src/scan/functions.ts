import type { PGliteInterface } from "@electric-sql/pglite";
import { stripSqlComments } from "../sql/split.js";
import type { SchemaInfo } from "../db/introspect.js";
import { OWASP, type Finding, type Severity } from "./findings.js";

/** A function the app defined. In an API-exposed schema, the API can call it as /rest/v1/rpc/<name>. */
export interface DatabaseFunction {
  schema: string;
  /** In a schema the API exposes, so callable from the browser. */
  exposed: boolean;
  name: string;
  /** e.g. "target_user uuid" */
  args: string;
  argNames: string[];
  /** e.g. "void", "SETOF posts", "boolean", "trigger" */
  returns: string;
  language: string;
  securityDefiner: boolean;
  searchPathSet: boolean;
  body: string;
  anonCanCall: boolean;
  authenticatedCanCall: boolean;
}

/**
 * Reads the functions the app defined, in any schema (helpers like
 * is_admin() often live in a private one), but not Supabase's own schemas or
 * functions that came with an extension.
 */
export async function readFunctions(db: PGliteInterface, exposedSchemas: string[]): Promise<DatabaseFunction[]> {
  const result = await db.query<{
    schema: string;
    name: string;
    args: string;
    arg_names: string[] | null;
    returns: string;
    language: string;
    security_definer: boolean;
    search_path_set: boolean;
    body: string | null;
    anon: boolean;
    authenticated: boolean;
  }>(
    `select n.nspname as schema, p.proname as name,
            pg_get_function_identity_arguments(p.oid) as args,
            p.proargnames::text[] as arg_names,
            pg_get_function_result(p.oid) as returns,
            l.lanname as language,
            p.prosecdef as security_definer,
            exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%') as search_path_set,
            p.prosrc as body,
            has_function_privilege('anon', p.oid, 'EXECUTE') as anon,
            has_function_privilege('authenticated', p.oid, 'EXECUTE') as authenticated
       from pg_proc p
       join pg_namespace n on n.oid = p.pronamespace
       join pg_language l on l.oid = p.prolang
      where n.nspname not in ('pg_catalog', 'information_schema', 'auth', 'storage', 'extensions', 'realtime',
                              'graphql', 'graphql_public', 'vault', 'pgsodium', 'net', 'supabase_functions', 'cron')
        and n.nspname not like 'pg\_%'
        and p.prokind = 'f'
        and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
      order by n.nspname, p.proname`,
  );
  return result.rows.map((r) => ({
    schema: r.schema,
    exposed: exposedSchemas.includes(r.schema),
    name: r.name,
    args: r.args,
    argNames: (r.arg_names ?? []).filter(Boolean),
    returns: r.returns,
    language: r.language,
    securityDefiner: r.security_definer,
    searchPathSet: r.search_path_set,
    body: r.body ?? "",
    anonCanCall: r.anon,
    authenticatedCanCall: r.authenticated,
  }));
}

/**
 * Functions are an easy way around RLS: a SECURITY DEFINER function runs
 * with its owner's rights, and Postgres lets everyone call new functions
 * unless EXECUTE is revoked. These checks read each function's code and
 * report the worst problem per function.
 */
export function functionFindings(functions: DatabaseFunction[], schema: SchemaInfo): Finding[] {
  const tables = new Set([
    ...schema.relations.map((r) => (r.schema === "public" ? r.name : `${r.schema}.${r.name}`)),
    "auth.users",
    "storage.objects",
    "storage.buckets",
  ]);
  const findings: Finding[] = [];
  for (const fn of functions) {
    if (!fn.exposed || (!fn.anonCanCall && !fn.authenticatedCanCall)) continue;
    if (/^(trigger|event_trigger)$/i.test(fn.returns)) continue; // triggers can't be called through the API
    const finding = sqlInjection(fn) ?? definerWrites(fn) ?? definerReads(fn, tables) ?? mutableSearchPath(fn);
    if (finding) findings.push(finding);
  }
  return findings;
}

function sqlInjection(fn: DatabaseFunction): Finding | null {
  if (fn.language !== "plpgsql") return null;
  const body = stripSqlComments(fn.body);
  const positional = fn.args.trim() === "" ? [] : fn.args.split(",").map((_, i) => `$${i + 1}`);
  const params = [...fn.argNames, ...positional];

  for (const m of body.matchAll(/\bexecute\b([^;]*)/gi)) {
    // Values after USING are passed as parameters, which is the safe way.
    const sql = m[1]!.replace(/\s+using\b[\s\S]*$/i, "");
    if (/^\s*(?:procedure|function)\b/i.test(sql)) continue; // part of a CREATE TRIGGER
    const code = sql.replace(/'(?:[^']|'')*'/g, "''"); // what's left outside string literals
    const param = params.find((p) => new RegExp(`(?<![\\w$])${escapeRegex(p)}(?![\\w$])`, "i").test(code));
    if (!param) continue;
    const whole = new RegExp(`^\\s*${escapeRegex(param)}\\s*$`, "i").test(code);
    const pasted =
      whole ||
      (/\|\|/.test(code) && !/quote_(?:literal|ident|nullable)\s*\(/i.test(code)) ||
      (/\bformat\s*\(/i.test(code) && /%s/.test(sql));
    if (!pasted) continue;

    const who = caller(fn);
    const severity: Severity = fn.securityDefiner ? "critical" : "high";
    return finding(fn, severity, {
      title: whole
        ? `${who} can run any SQL they like through ${fn.name}(): it executes "${param}" as a query.`
        : `${fn.name}() pastes "${param}" into a SQL query (SQL injection).`,
      detail: fn.securityDefiner
        ? "It's security definer, so that SQL runs with the function owner's rights: no RLS, every table."
        : "It runs with the caller's rights, so RLS still applies, but callers can change what the query does.",
      fix: "Pass values separately: EXECUTE '... where title ilike $1' USING '%' || term || '%', or format('%L', value). Never paste text into SQL.",
      rule: "db-function-sql-injection",
      owasp: OWASP.injection,
    });
  }
  return null;
}

function definerWrites(fn: DatabaseFunction): Finding | null {
  if (!fn.securityDefiner || checksCaller(fn)) return null;
  const body = stripSqlComments(fn.body);
  const writes: { verb: string; table: string }[] = [];
  for (const m of body.matchAll(/\b(insert\s+into|update|delete\s+from|truncate(?:\s+table)?)\s+((?:only\s+)?[\w."]+)/gi)) {
    const verb = m[1]!.toLowerCase().split(/\s+/)[0]!;
    if (verb === "update" && !/^\s*[\w."]+\s+(?:as\s+\w+\s+)?set\b/i.test(body.slice(m.index! + m[1]!.length))) continue;
    writes.push({ verb, table: shortTable(m[2]!) });
  }
  if (writes.length === 0) return null;

  const destructive = writes.some((w) => w.verb === "delete" || w.verb === "truncate");
  const verbs = unique(writes.map((w) => ({ insert: "add", update: "change", delete: "delete", truncate: "delete" })[w.verb]!));
  const tables = unique(writes.map((w) => w.table));
  return finding(fn, destructive ? "high" : "medium", {
    title: `${caller(fn)} can call ${fn.name}() to ${joinWords(verbs)} rows in ${joinWords(tables)}, skipping RLS.`,
    detail:
      "It's security definer (runs with its owner's rights) and never checks auth.uid()." +
      (destructive ? "" : " Fine for something like a view counter; not if it touches data that belongs to users."),
    fix: `Check the caller inside it (… where user_id = auth.uid()), or make it security invoker so RLS applies. If only your server uses it: revoke execute on function ${fn.schema}.${fn.name} from public, anon, authenticated;`,
    rule: "db-function-bypasses-rls",
    owasp: OWASP.accessControl,
  });
}

function definerReads(fn: DatabaseFunction, knownTables: Set<string>): Finding | null {
  if (!fn.securityDefiner || checksCaller(fn)) return null;
  // Booleans and numbers (has_role(), count_x()) say little; rows and text can leak data.
  if (/^(boolean|bool|void|integer|int|bigint|smallint|numeric|real|double precision)$/i.test(fn.returns)) return null;
  const body = stripSqlComments(fn.body);
  // Only names that are tables: `extract(epoch from created_at)` also says "from".
  const named = [...body.matchAll(/(?<!\bdistinct\s+)\b(?:from|join)\s+((?:only\s+)?[a-z_][\w."]*)(?![\w."]|\s*\()/gi)];
  const tables = unique(named.map((m) => shortTable(m[1]!)).filter((t) => knownTables.has(t) || t.includes(".")));
  if (tables.length === 0) return null;
  const users = tables.some((t) => t === "auth.users");
  return finding(fn, users ? "high" : "medium", {
    title: `${caller(fn)} can call ${fn.name}() and get data from ${joinWords(tables)} without RLS.`,
    detail: users
      ? "It reads auth.users, which holds every user's email and sign-in details."
      : "It's security definer and never checks auth.uid(). Fine if everything it returns is meant to be public.",
    fix: `Filter by the caller inside it (… where user_id = auth.uid()), or make it security invoker so RLS applies. If only your server uses it: revoke execute on function ${fn.schema}.${fn.name} from public, anon, authenticated;`,
    rule: "db-function-bypasses-rls",
    owasp: OWASP.accessControl,
  });
}

function mutableSearchPath(fn: DatabaseFunction): Finding | null {
  if (!fn.securityDefiner || fn.searchPathSet) return null;
  return finding(fn, "low", {
    title: `${fn.name}() is security definer but doesn't set search_path.`,
    detail: "Supabase's own linter flags this: someone who can create objects in another schema could make it call their code with the function's rights.",
    fix: `Add \`set search_path = ''\` to the function and use schema-qualified names (public.table).`,
    rule: "db-function-search-path",
    owasp: OWASP.misconfiguration,
  });
}

function finding(
  fn: DatabaseFunction,
  severity: Severity,
  parts: Pick<Finding, "title" | "detail" | "fix" | "rule" | "owasp">,
): Finding {
  const name = fn.schema === "public" ? fn.name : `${fn.schema}.${fn.name}`;
  return { severity, targetKey: `function:${fn.schema}.${fn.name}`, label: `${name}()`, ...parts };
}

/** Uses the caller's identity, so it can limit what they reach. */
function checksCaller(fn: DatabaseFunction): boolean {
  return /\bauth\.(?:uid|jwt|role|email)\s*\(|request\.jwt\.claim/i.test(fn.body);
}

function caller(fn: DatabaseFunction): string {
  return fn.anonCanCall ? "Anyone" : "Any signed-in user";
}

function shortTable(name: string): string {
  const clean = name.replace(/^only\s+/i, "").replace(/"/g, "").toLowerCase();
  return clean.startsWith("public.") ? clean.slice("public.".length) : clean;
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

function joinWords(words: string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
