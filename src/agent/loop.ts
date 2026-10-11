import Anthropic from "@anthropic-ai/sdk";
import { errorMessage } from "../db/load.js";
import type { ModelClient } from "./model.js";
import { firstMessage, SYSTEM_PROMPT } from "./prompt.js";
import { runTool, TOOLS, type ToolContext } from "./tools.js";
import type { Trace } from "./trace.js";

export interface TokenUsage {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

export interface AgentOutcome {
  status: "saved" | "rejected" | "stopped" | "refused" | "error";
  file?: string;
  /** The agent's last words, or what went wrong. */
  message?: string;
  turns: number;
  usage: TokenUsage;
}

type ContentBlock = Anthropic.Beta.BetaContentBlock;

/**
 * The agent loop for one table, written out by hand so every step is visible:
 *
 *   ask the model -> run the tools it asked for -> send back the results -> repeat
 *
 * It ends when the person saves or rejects a fix, when the model stops
 * calling tools, or after `maxTurns` model calls. The message history is
 * append-only: we never edit earlier turns, which keeps the prompt cache warm
 * and keeps the model's reasoning blocks valid.
 */
export async function runFixAgent(
  model: ModelClient,
  ctx: ToolContext,
  trace: Trace,
  maxTurns = 15,
): Promise<AgentOutcome> {
  const usage: TokenUsage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  const labels = ctx.project.targets.map((t) => t.label);
  const messages: Anthropic.Beta.BetaMessageParam[] = [
    { role: "user", content: firstMessage(ctx.target, ctx.findings, labels) },
  ];
  const session = ctx.target.key;
  trace.write({ session, event: "start", model: model.name, prompt: messages[0]!.content });

  for (let turn = 1; turn <= maxTurns; turn++) {
    let response: Anthropic.Beta.BetaMessage;
    try {
      response = await model.create({ system: SYSTEM_PROMPT, tools: TOOLS, messages });
    } catch (error) {
      const message = error instanceof Anthropic.APIError ? `API error ${error.status}: ${error.message}` : errorMessage(error);
      trace.write({ session, event: "error", turn, message });
      return { status: "error", message, turns: turn, usage };
    }

    addUsage(usage, response.usage);
    trace.write({
      session,
      event: "model",
      turn,
      model: response.model,
      stop_reason: response.stop_reason,
      usage: response.usage,
      blocks: response.content.map(summarizeBlock),
    });

    if (response.stop_reason === "refusal") {
      return { status: "refused", message: "The model declined this request.", turns: turn, usage };
    }
    if (response.stop_reason === "max_tokens") {
      return { status: "error", message: "The model's reply was cut off (max_tokens).", turns: turn, usage };
    }

    messages.push({ role: "assistant", content: echoable(response.content) });
    const toolUses = response.content.filter((b): b is Anthropic.Beta.BetaToolUseBlock => b.type === "tool_use");
    const text = response.content
      .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === "text")
      .map((b) => b.text)
      .join("\n")
      .trim();

    if (toolUses.length === 0) {
      return { status: finalStatus(ctx), file: ctx.state.savedFile, message: text || undefined, turns: turn, usage };
    }

    // Run every requested tool, then send all results back in one message.
    const results: Anthropic.Beta.BetaToolResultBlockParam[] = [];
    for (const call of toolUses) {
      const output = await runTool(call.name, call.input, ctx);
      trace.write({ session, event: "tool", turn, name: call.name, input: call.input, output: output.content, error: output.isError });
      results.push({ type: "tool_result", tool_use_id: call.id, content: output.content, is_error: output.isError });
    }
    messages.push({ role: "user", content: results });

    // Saved or rejected: the job is done, no need to pay for another reply.
    if (ctx.state.status !== "working") {
      return { status: finalStatus(ctx), file: ctx.state.savedFile, message: text || undefined, turns: turn, usage };
    }
  }
  return { status: "stopped", message: `Stopped after ${maxTurns} turns without a saved fix.`, turns: maxTurns, usage };
}

function finalStatus(ctx: ToolContext): AgentOutcome["status"] {
  return ctx.state.status === "saved" ? "saved" : ctx.state.status === "rejected" ? "rejected" : "stopped";
}

function addUsage(total: TokenUsage, usage: Anthropic.Beta.BetaUsage): void {
  total.input += usage.input_tokens;
  total.output += usage.output_tokens;
  total.cacheRead += usage.cache_read_input_tokens ?? 0;
  total.cacheWrite += usage.cache_creation_input_tokens ?? 0;
}

/**
 * The assistant content we send back on the next request. Normally the reply
 * as-is (thinking blocks included). If a server-side fallback happened
 * mid-reply, blocks before the last `fallback` marker that the next model
 * can't use (thinking, tool calls) are left out, as the API docs require.
 */
function echoable(content: ContentBlock[]): Anthropic.Beta.BetaContentBlockParam[] {
  const lastFallback = content.map((b) => b.type as string).lastIndexOf("fallback");
  const kept =
    lastFallback === -1
      ? content
      : content.filter(
          (block, i) =>
            i >= lastFallback ||
            !["thinking", "redacted_thinking", "tool_use", "server_tool_use"].includes(block.type),
        );
  return kept as unknown as Anthropic.Beta.BetaContentBlockParam[];
}

function summarizeBlock(block: ContentBlock): Record<string, unknown> {
  switch (block.type) {
    case "text":
      return { type: "text", text: block.text };
    case "tool_use":
      return { type: "tool_use", name: block.name, input: block.input };
    case "thinking":
      return { type: "thinking", chars: block.thinking.length };
    default:
      return { type: block.type };
  }
}
