# Vibesecure

An open-source AI agent that finds data leaks in Supabase apps built with Lovable, Bolt and similar tools, then fixes them, with you approving every change.

Plan v2 · 2026-10-11 · Small, free, public. Built by one student in about 4 weeks.

## Why this project

- **The problem is real and easy to explain.** AI app builders often ship databases that anyone can read. In 2025, 170+ Lovable apps leaked data through policies that let anyone in (CVE-2025-48757). In 2026, Moltbook exposed 1.5M API keys because row-level security (RLS) was missing.
- **It's small:** one person, about 4 weeks, $0.
- **It shows the skills you want to show:**
  - An agent that uses tools, asks a human when it's unsure, proves its own fix, and never acts without approval.
  - Real Postgres depth: roles, RLS and grants. This ties straight into your DBMS work.

## What a user sees

```text
$ npx vibesecure scan

  Who can touch another user's data?
  table      anyone on the internet   another signed-in user
  profiles   🔒 no                    🔒 no
  posts      ⚠️ read + edit           ⚠️ read + edit
  notes      ⚠️ read + edit           ⚠️ read + edit

  2 tables are open. Run `npx vibesecure fix` to fix them with an AI agent.

$ npx vibesecure fix

  Agent  `posts` has a user_id column, and your app only ever shows people
         their own posts (src/pages/MyPosts.tsx:14). Should posts be private?
  ? Who should read posts?  › Only the owner / Everyone / Let me explain
  Agent  Proposed fix: turn on RLS and add owner-only policies (SQL shown)
  Agent  Checked: strangers are now blocked, and the owner can still read and edit ✅
  ? Save as supabase/migrations/20261020120000_vibesecure_posts.sql?  (y/n)
```

## How it works

1. **Scan.** No AI and no API key needed.
   - Read the SQL files in `supabase/migrations/` (Lovable keeps database changes here; check this on your own Lovable app in week 1).
   - Load them into **PGlite**, which is real Postgres compiled to WebAssembly. It runs inside Node, so there's no Docker and no connection to the real database.
   - Add a small Supabase setup: the `anon` and `authenticated` roles and `auth.uid()`.
   - Create two fake users, each with their own rows.
   - Test what an anonymous visitor and *the other user* can read, insert, update and delete.
2. **Fix (the agent).** For each open table, a Claude agent runs a loop with four tools:
   - `read_schema(table)`: the table's columns, policies and grants.
   - `find_usages(table)`: where the app's code queries that table.
   - `ask_human(question, options)`: used when the agent can't tell what you intended.
   - `try_fix(sql)`: applies the SQL to a throwaway copy and runs the scan again.

   The loop stops only when the scan passes *and* the owner still has access. Then you approve, and it writes a migration file.
3. **Guardrails.**
   - The agent never touches a real database.
   - Nothing is written without your "yes".
   - Every step is logged to `.vibesecure/trace.jsonl`, so you can see exactly what the agent did.

**Step 1 is already tested.** PGlite handles Supabase-style roles and RLS correctly. A table with RLS turned off and one with an "allow everyone" policy both showed as open, and the owner-only table was blocked for both a stranger and another user.

**Cost.** `scan` needs no key. For `fix`, users bring their own Anthropic API key. Everything runs on the user's machine, so other people using it costs you nothing.

## Stack

TypeScript on Node 22+, PGlite, the official Anthropic SDK, a small CLI and prompt library (for example commander with @clack/prompts), and Vitest for tests. Published on npm and GitHub.

## 4 weeks (about 10–12 hours a week)

| Week | Build | Done when |
|---|---|---|
| 1 | `scan`: load migrations into PGlite, add the Supabase setup and fake users, print the access table | It gives correct results on a deliberately leaky demo app |
| 2 | A plain-English report. Three fix templates: owner-only, public read with owner write, and private. Check each fix by running the scan again. | The templates fix the demo app without any AI |
| 3 | `fix`: the Claude agent loop with the four tools, human approval, and the trace log | The agent fixes a case the templates can't, after asking you one question |
| 4 | A README with a GIF, the demo repo, publishing to npm, launch posts | Someone you don't know runs it |

**Launch:** post on r/Supabase, r/lovable, r/vibecoding, the Lovable Discord and LinkedIn or X. Write a blog episode on how the agent works.

**Later, only if people use it:**
- A GitHub Action that runs `scan` on every push.
- A browser version. PGlite also runs in the browser, so nothing would be uploaded.

## Two rules

- Only scan code you have locally. Never point it at someone else's live app.
- The agent works on a throwaway copy, never on a real database.

## Already out there

SupaShield tests RLS against a live database connection. Vibesecure differs in two ways:

- It works from the repo alone. That suits Lovable Cloud users, who can't connect to their own database.
- It adds the agent that fixes problems with your approval.
