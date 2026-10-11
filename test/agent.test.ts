import { readFileSync } from "node:fs";
import { join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ModelClient, ModelRequest } from "../src/agent/model.js";
import { Trace } from "../src/agent/trace.js";
import { findUsages } from "../src/agent/usages.js";
import { fixWithAgent } from "../src/fix/session.js";
import { scanProject, type ScanResult } from "../src/scan/index.js";
import { ScriptedHuman } from "../src/ui/human.js";
import { copyOfExampleApp } from "./helpers.js";

/** A stand-in for Claude that replays a fixed list of replies and records what it was sent. */
class ScriptedModel implements ModelClient {
  readonly name = "scripted";
  readonly requests: ModelRequest[] = [];
  constructor(private readonly replies: Anthropic.Beta.BetaMessage[]) {}

  async create(request: ModelRequest): Promise<Anthropic.Beta.BetaMessage> {
    // Copy the messages: the loop keeps appending to the same array.
    this.requests.push({ ...request, messages: [...request.messages] });
    const reply = this.replies.shift();
    if (!reply) throw new Error("ScriptedModel ran out of replies");
    return reply;
  }
}

let callId = 0;
function toolCall(name: string, input: Record<string, unknown>): Anthropic.Beta.BetaToolUseBlock {
  return { type: "tool_use", id: `toolu_${++callId}`, name, input } as Anthropic.Beta.BetaToolUseBlock;
}

function reply(content: unknown[], stopReason: Anthropic.Beta.BetaStopReason = "tool_use"): Anthropic.Beta.BetaMessage {
  return {
    id: `msg_${++callId}`,
    type: "message",
    role: "assistant",
    model: "scripted",
    content,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: { input_tokens: 1200, output_tokens: 300, cache_read_input_tokens: 1000, cache_creation_input_tokens: 0 },
  } as unknown as Anthropic.Beta.BetaMessage;
}

const LEAKY_FIX = `alter table public.notes enable row level security;`;
const GOOD_FIX = `
alter table public.notes enable row level security;
drop policy if exists "Enable all access" on public.notes;
create policy "Owners can read their notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Owners can add notes" on public.notes
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Owners can edit their notes" on public.notes
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Owners can delete their notes" on public.notes
  for delete to authenticated using ((select auth.uid()) = user_id);
`;

let scan: ScanResult;
let projectDir: string;

beforeAll(async () => {
  projectDir = copyOfExampleApp();
  scan = await scanProject(projectDir);
});

afterAll(async () => {
  await scan.project.db.close();
});

/** Pulls the tool results the loop sent back to the model in a given request. */
function toolResults(request: ModelRequest): Anthropic.Beta.BetaToolResultBlockParam[] {
  const last = request.messages[request.messages.length - 1]!;
  return (last.content as Anthropic.Beta.BetaToolResultBlockParam[]).filter((b) => b.type === "tool_result");
}

describe("the fix agent", () => {
  it("investigates, asks, tests until it passes, and saves only after approval", async () => {
    const notes = scan.project.targets.find((t) => t.key === "public.notes")!;
    const model = new ScriptedModel([
      reply([toolCall("read_table", { name: "notes" })]),
      reply([toolCall("find_usages", { name: "notes" })]),
      reply([
        toolCall("ask_human", {
          question: "Should people only see their own notes?",
          options: ["Yes, only their own", "No, everyone can read them"],
        }),
      ]),
      reply([toolCall("test_fix", { sql: LEAKY_FIX, read: "owner", write: "owner" })]),
      reply([toolCall("propose_fix", { sql: LEAKY_FIX, read: "owner", write: "owner", summary: "too early" })]),
      reply([toolCall("test_fix", { sql: GOOD_FIX, read: "owner", write: "owner" })]),
      reply([
        toolCall("propose_fix", {
          sql: GOOD_FIX,
          read: "owner",
          write: "owner",
          summary: "Anyone could read and change every note. Now each person can only see and change their own.",
        }),
      ]),
    ]);
    const human = new ScriptedHuman(["Yes, only their own", "save"]);
    const trace = new Trace(join(projectDir, ".vibesecure", "trace.jsonl"));

    const result = await fixWithAgent(scan, notes, human, model, trace);

    expect(result.status).toBe("saved");
    expect(readFileSync(result.file!, "utf8")).toContain('create policy "Owners can read their notes"');
    expect(result.outcome.turns).toBe(7);

    // What the tools told the model along the way.
    const [readTable] = toolResults(model.requests[1]!);
    expect(JSON.parse(readTable!.content as string)).toMatchObject({ name: "notes", owner_column: "user_id" });
    const [usages] = toolResults(model.requests[2]!);
    expect(usages!.content).toContain("src/pages/Notes.tsx");
    const [answer] = toolResults(model.requests[3]!);
    expect(JSON.parse(answer!.content as string)).toEqual({ answer: "Yes, only their own" });
    const [failedTest] = toolResults(model.requests[4]!);
    expect(JSON.parse(failedTest!.content as string).passed).toBe(false);
    // Proposing SQL that hasn't passed is refused without bothering the person.
    const [refused] = toolResults(model.requests[5]!);
    expect(refused!.is_error).toBe(true);
    const [passedTest] = toolResults(model.requests[6]!);
    expect(JSON.parse(passedTest!.content as string).passed).toBe(true);

    // The person was asked exactly twice: the agent's question and the save decision.
    expect(human.transcript.filter((line) => line.startsWith("?"))).toHaveLength(2);

    // Every model reply and tool call is in the trace.
    const events = readFileSync(trace.path!, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(events.filter((e) => e.event === "model")).toHaveLength(7);
    expect(events.filter((e) => e.event === "tool").map((e) => e.name)).toEqual([
      "read_table", "find_usages", "ask_human", "test_fix", "propose_fix", "test_fix", "propose_fix",
    ]);
  });

  it("stops and saves nothing when the person rejects the fix", async () => {
    const notes = scan.project.targets.find((t) => t.key === "public.notes")!;
    const model = new ScriptedModel([
      reply([toolCall("propose_fix", { sql: GOOD_FIX, read: "owner", write: "owner", summary: "Lock notes to owners." })]),
    ]);
    const result = await fixWithAgent(scan, notes, new ScriptedHuman(["reject"]), model, new Trace(null));
    expect(result.status).toBe("rejected");
    expect(result.file).toBeUndefined();
    expect(model.requests).toHaveLength(1);
  });

  it("passes the person's requested changes back to the agent", async () => {
    const notes = scan.project.targets.find((t) => t.key === "public.notes")!;
    const model = new ScriptedModel([
      reply([toolCall("propose_fix", { sql: GOOD_FIX, read: "owner", write: "owner", summary: "Lock notes to owners." })]),
      reply([{ type: "text", text: "Understood, I'll leave notes as they are." }], "end_turn"),
    ]);
    const human = new ScriptedHuman(["change", "Admins should also be able to read notes"]);
    const result = await fixWithAgent(scan, notes, human, model, new Trace(null));
    const [feedback] = toolResults(model.requests[1]!);
    expect(JSON.parse(feedback!.content as string).feedback).toBe("Admins should also be able to read notes");
    expect(result.status).toBe("failed");
    expect(result.outcome.message).toContain("Understood");
  });

  it("handles a refusal without crashing", async () => {
    const notes = scan.project.targets.find((t) => t.key === "public.notes")!;
    const model = new ScriptedModel([reply([], "refusal")]);
    const result = await fixWithAgent(scan, notes, new ScriptedHuman([]), model, new Trace(null));
    expect(result.outcome.status).toBe("refused");
  });

  it("rejects tool input that doesn't match the schema", async () => {
    const notes = scan.project.targets.find((t) => t.key === "public.notes")!;
    const model = new ScriptedModel([
      reply([toolCall("test_fix", { sql: GOOD_FIX, read: "everyone", write: "owner" })]),
      reply([{ type: "text", text: "Giving up." }], "end_turn"),
    ]);
    await fixWithAgent(scan, notes, new ScriptedHuman([]), model, new Trace(null));
    const [result] = toolResults(model.requests[1]!);
    expect(result!.is_error).toBe(true);
    expect(result!.content).toContain("Invalid input");
  });
});

describe("findUsages", () => {
  it("finds supabase-js calls with their chained filters", () => {
    const { matches } = findUsages(projectDir, "posts", "table");
    expect(matches.map((m) => m.file).sort()).toEqual([
      "src/pages/MyPosts.tsx",
      "src/pages/MyPosts.tsx",
      "src/pages/Search.tsx",
    ]);
    expect(matches[0]!.code).toContain('.eq("user_id", user.id)');
  });

  it("finds storage calls for buckets", () => {
    const { matches } = findUsages(projectDir, "invoices", "bucket");
    expect(matches).toHaveLength(1);
    expect(matches[0]!.file).toBe("src/pages/Post.tsx");
  });
});
