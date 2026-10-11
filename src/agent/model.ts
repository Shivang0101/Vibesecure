import Anthropic from "@anthropic-ai/sdk";

export type Effort = "low" | "medium" | "high" | "xhigh" | "max";

export const DEFAULT_MODEL = "claude-opus-5-5";
export const DEFAULT_EFFORT: Effort = "medium";

export interface ModelRequest {
  system: string;
  tools: Anthropic.Beta.BetaTool[];
  messages: Anthropic.Beta.BetaMessageParam[];
}

/** The one thing the agent loop needs from a model. Tests pass a scripted fake. */
export interface ModelClient {
  readonly name: string;
  create(request: ModelRequest): Promise<Anthropic.Beta.BetaMessage>;
}

/**
 * Calls Claude through the official SDK. The client reads ANTHROPIC_API_KEY
 * (or an `ant auth login` profile) from the environment.
 *
 * - Thinking is adaptive on current models; `effort` sets how hard it thinks.
 * - Top-level cache_control caches the growing conversation between turns.
 * - Server-side fallbacks retry a safety-classifier decline on another model,
 *   so a false positive on security-flavoured SQL doesn't stop the run.
 */
export class AnthropicModel implements ModelClient {
  private readonly client: Anthropic;

  constructor(
    readonly name: string = DEFAULT_MODEL,
    private readonly effort: Effort = DEFAULT_EFFORT,
    client?: Anthropic,
  ) {
    this.client = client ?? new Anthropic();
  }

  create(request: ModelRequest): Promise<Anthropic.Beta.BetaMessage> {
    const fallbacks = supportsServerFallback(this.name)
      ? { betas: ["server-side-fallback-2026-07-01" as const], fallbacks: "default" as const }
      : {};
    return this.client.beta.messages.create({
      model: this.name,
      max_tokens: 16000,
      system: request.system,
      tools: request.tools,
      messages: request.messages,
      output_config: { effort: this.effort },
      cache_control: { type: "ephemeral" },
      ...fallbacks,
    });
  }
}

/** Server-side fallbacks exist for the current Opus, Fable and Sonnet models, not Haiku. */
function supportsServerFallback(model: string): boolean {
  return /^claude-(opus-5|fable-5|sonnet-5-5)/.test(model);
}

/** True when an API key or auth token is set, so the AI agent can run. */
export function hasAnthropicCredentials(): boolean {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}
