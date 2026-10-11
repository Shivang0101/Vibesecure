import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/**
 * An append-only log of everything the agent did: each model reply, each
 * tool call and result, and each answer from the person. One JSON object per
 * line, so it's easy to read back or replay.
 */
export class Trace {
  constructor(readonly path: string | null) {
    if (path) mkdirSync(dirname(path), { recursive: true });
  }

  write(event: Record<string, unknown>): void {
    if (!this.path) return;
    appendFileSync(this.path, `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);
  }
}
