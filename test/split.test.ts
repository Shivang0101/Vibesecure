import { describe, expect, it } from "vitest";
import { splitSqlStatements, stripSqlComments } from "../src/sql/split.js";

describe("splitSqlStatements", () => {
  it("splits on semicolons", () => {
    expect(splitSqlStatements("select 1; select 2;")).toEqual(["select 1", "select 2"]);
  });

  it("ignores semicolons inside strings, quoted names and comments", () => {
    const sql = `
      insert into t values ('a;b', 'it''s; fine');
      -- a comment; with a semicolon
      create table "weird;name" (id int);
      /* block; /* nested; */ still comment; */ select 3;
    `;
    expect(splitSqlStatements(sql)).toHaveLength(3);
  });

  it("keeps dollar-quoted function bodies together", () => {
    const sql = `
      create function f() returns trigger language plpgsql as $$
      begin
        insert into a values (1);
        return new;
      end;
      $$;
      create function g() returns int language sql as $body$ select 1; $body$;
      select 1;
    `;
    const statements = splitSqlStatements(sql);
    expect(statements).toHaveLength(3);
    expect(statements[0]).toContain("return new;");
  });

  it("does not treat $1 parameters as dollar quotes", () => {
    expect(splitSqlStatements("prepare p as select $1; select 2;")).toEqual(["prepare p as select $1", "select 2"]);
  });

  it("handles E'' strings with backslash escapes", () => {
    expect(splitSqlStatements(String.raw`select E'it\'s; ok'; select 2;`)).toHaveLength(2);
  });

  it("drops empty and comment-only statements", () => {
    expect(splitSqlStatements(";; -- just a comment\n ;")).toEqual([]);
  });
});

describe("stripSqlComments", () => {
  it("removes comments and squeezes whitespace", () => {
    expect(stripSqlComments("alter  table x -- hi\n enable /* c */ row level security")).toBe(
      "alter table x enable row level security",
    );
  });
});
