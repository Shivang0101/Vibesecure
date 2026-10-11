/**
 * Split a SQL script into individual statements.
 *
 * Postgres runs a multi-statement script all-or-nothing, so one unsupported
 * line (say `create extension pg_cron`) would throw away a whole migration.
 * Splitting lets us run statements one by one and skip only the ones that fail.
 *
 * A semicolon only ends a statement when it is outside quotes, comments and
 * dollar-quoted bodies like $$ ... $$ or $fn$ ... $fn$ (used by functions).
 */
export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let start = 0;
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (ch === "-" && next === "-") {
      i = skipLineComment(sql, i);
    } else if (ch === "/" && next === "*") {
      i = skipBlockComment(sql, i);
    } else if (ch === "'") {
      i = skipSingleQuoted(sql, i, isEscapeString(sql, i));
    } else if (ch === '"') {
      i = skipDoubleQuoted(sql, i);
    } else if (ch === "$" && dollarTagAt(sql, i) !== null) {
      i = skipDollarQuoted(sql, i, dollarTagAt(sql, i)!);
    } else if (ch === ";") {
      pushStatement(statements, sql.slice(start, i));
      start = i + 1;
      i++;
    } else {
      i++;
    }
  }
  pushStatement(statements, sql.slice(start));
  return statements;
}

/** Removes comments and whitespace, so callers can test what a statement starts with. */
export function stripSqlComments(statement: string): string {
  let out = "";
  let i = 0;
  while (i < statement.length) {
    const ch = statement[i];
    const next = statement[i + 1];
    if (ch === "-" && next === "-") {
      i = skipLineComment(statement, i);
      out += " ";
    } else if (ch === "/" && next === "*") {
      i = skipBlockComment(statement, i);
      out += " ";
    } else if (ch === "'") {
      const end = skipSingleQuoted(statement, i, isEscapeString(statement, i));
      out += statement.slice(i, end);
      i = end;
    } else if (ch === '"') {
      const end = skipDoubleQuoted(statement, i);
      out += statement.slice(i, end);
      i = end;
    } else if (ch === "$" && dollarTagAt(statement, i) !== null) {
      const end = skipDollarQuoted(statement, i, dollarTagAt(statement, i)!);
      out += statement.slice(i, end);
      i = end;
    } else {
      out += ch;
      i++;
    }
  }
  return out.replace(/\s+/g, " ").trim();
}

function pushStatement(statements: string[], raw: string): void {
  const trimmed = raw.trim();
  if (trimmed.length > 0 && stripSqlComments(trimmed).length > 0) {
    statements.push(trimmed);
  }
}

function skipLineComment(sql: string, i: number): number {
  const end = sql.indexOf("\n", i);
  return end === -1 ? sql.length : end + 1;
}

/** Postgres block comments can nest, so we track the depth. */
function skipBlockComment(sql: string, i: number): number {
  let depth = 0;
  while (i < sql.length) {
    if (sql[i] === "/" && sql[i + 1] === "*") {
      depth++;
      i += 2;
    } else if (sql[i] === "*" && sql[i + 1] === "/") {
      depth--;
      i += 2;
      if (depth === 0) return i;
    } else {
      i++;
    }
  }
  return sql.length;
}

/** E'...' strings allow backslash escapes like E'it\'s'. */
function isEscapeString(sql: string, quoteIndex: number): boolean {
  const prev = sql[quoteIndex - 1];
  const beforePrev = sql[quoteIndex - 2] ?? " ";
  return (prev === "E" || prev === "e") && !/[A-Za-z0-9_]/.test(beforePrev);
}

function skipSingleQuoted(sql: string, i: number, backslashEscapes: boolean): number {
  i++; // opening quote
  while (i < sql.length) {
    const ch = sql[i];
    if (backslashEscapes && ch === "\\") {
      i += 2;
    } else if (ch === "'" && sql[i + 1] === "'") {
      i += 2; // '' is an escaped quote
    } else if (ch === "'") {
      return i + 1;
    } else {
      i++;
    }
  }
  return sql.length;
}

function skipDoubleQuoted(sql: string, i: number): number {
  i++;
  while (i < sql.length) {
    if (sql[i] === '"' && sql[i + 1] === '"') {
      i += 2;
    } else if (sql[i] === '"') {
      return i + 1;
    } else {
      i++;
    }
  }
  return sql.length;
}

/**
 * Returns the full tag ("$$" or "$body$") if a dollar quote opens at `i`.
 * `$1` style parameters and identifiers containing `$` are not dollar quotes.
 */
function dollarTagAt(sql: string, i: number): string | null {
  const prev = sql[i - 1];
  if (prev !== undefined && /[A-Za-z0-9_$]/.test(prev)) return null;
  const match = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
  return match ? match[0] : null;
}

function skipDollarQuoted(sql: string, i: number, tag: string): number {
  const end = sql.indexOf(tag, i + tag.length);
  return end === -1 ? sql.length : end + tag.length;
}
