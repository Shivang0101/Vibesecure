import { splitSqlStatements, stripSqlComments } from "../sql/split.js";
import type { Target } from "../scan/targets.js";

/**
 * A fix may only change *who can access* the target: RLS, policies, grants
 * and view security. Anything else (dropping tables, deleting rows, new
 * functions that run with elevated rights) is refused, whoever wrote it.
 * Returns a list of problems; empty means the SQL is allowed.
 */
export function guardFixSql(sql: string, target: Target): string[] {
  const statements = splitSqlStatements(sql);
  if (statements.length === 0) return ["The fix is empty."];

  const problems: string[] = [];
  for (const statement of statements) {
    const flat = stripSqlComments(statement);
    const lower = flat.toLowerCase();
    const relation = relationIn(lower);

    if (!ALLOWED.some((pattern) => pattern.test(lower))) {
      problems.push(`Not allowed in a fix (only RLS, policy, grant and view-security changes are): ${short(flat)}`);
      continue;
    }
    if (relation === null || !sameRelation(relation, target)) {
      problems.push(`A fix for ${target.label} may only change ${expectedName(target)}: ${short(flat)}`);
    }
  }
  return problems;
}

const NAME = String.raw`(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*)(?:\.(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*))?`;
/** End of a name: whitespace, an opening bracket or the end. (\b fails after a closing quote.) */
const END = String.raw`(?=[\s(]|$)`;

const ALLOWED: RegExp[] = [
  new RegExp(String.raw`^alter table (?:only )?(?:if exists )?${NAME} (?:enable|force) row level security$`),
  new RegExp(String.raw`^create policy ${NAME} on ${NAME}${END}`),
  new RegExp(String.raw`^drop policy (?:if exists )?${NAME} on ${NAME}$`),
  new RegExp(String.raw`^alter policy ${NAME} on ${NAME}${END}`),
  new RegExp(String.raw`^revoke [a-z, ]+ on (?:table )?${NAME} from [a-z_, "]+$`),
  new RegExp(String.raw`^grant (?:select|insert|update|delete)(?: ?, ?(?:select|insert|update|delete))* on (?:table )?${NAME} to (?:anon|authenticated|service_role)(?: ?, ?(?:anon|authenticated|service_role))*$`),
  new RegExp(String.raw`^alter view (?:if exists )?${NAME} set \( ?security_invoker ?= ?(?:on|true) ?\)$`),
  new RegExp(String.raw`^comment on (?:policy ${NAME} on|table|view) ${NAME} is\b`),
];

/** Finds the table or view a statement acts on. */
function relationIn(lower: string): string | null {
  const patterns = [
    new RegExp(String.raw`^alter table (?:only )?(?:if exists )?(${NAME})`),
    new RegExp(String.raw`^(?:create|alter) policy ${NAME} on (${NAME})`),
    new RegExp(String.raw`^drop policy (?:if exists )?${NAME} on (${NAME})`),
    new RegExp(String.raw`^(?:revoke|grant) [a-z, ]+ on (?:table )?(${NAME})`),
    new RegExp(String.raw`^alter view (?:if exists )?(${NAME})`),
    new RegExp(String.raw`^comment on policy ${NAME} on (${NAME})`),
    new RegExp(String.raw`^comment on (?:table|view) (${NAME})`),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(lower);
    if (match) return match[1]!;
  }
  return null;
}

function sameRelation(name: string, target: Target): boolean {
  const parts = name.split(".").map((p) => p.replace(/^"|"$/g, "").replace(/""/g, '"'));
  const [schema, rel] = parts.length === 2 ? [parts[0]!, parts[1]!] : ["public", parts[0]!];
  return schema === target.relation.schema.toLowerCase() && rel === target.relation.name.toLowerCase();
}

function expectedName(target: Target): string {
  return `${target.relation.schema}.${target.relation.name}`;
}

function short(statement: string): string {
  return statement.length > 120 ? `${statement.slice(0, 117)}...` : statement;
}
