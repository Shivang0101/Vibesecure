import * as clack from "@clack/prompts";
import pc from "picocolors";

export interface Choice {
  value: string;
  label: string;
  hint?: string;
}

/**
 * Everything the tool asks or tells the person at the keyboard goes through
 * this interface. The terminal version uses clack prompts; tests use a
 * scripted version with pre-recorded answers.
 */
export interface HumanIO {
  choose(question: string, choices: Choice[]): Promise<string>;
  ask(question: string, placeholder?: string): Promise<string>;
  confirm(question: string): Promise<boolean>;
  /** Shows a block of text, like SQL or a summary, with a title. */
  show(title: string, body: string): void;
  /** One line of agent activity, e.g. "Reading posts". */
  step(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  success(message: string): void;
}

export class CancelledError extends Error {
  constructor() {
    super("Cancelled.");
  }
}

export class TerminalHuman implements HumanIO {
  async choose(question: string, choices: Choice[]): Promise<string> {
    const answer = await clack.select({ message: question, options: choices });
    if (clack.isCancel(answer)) throw new CancelledError();
    return answer;
  }

  async ask(question: string, placeholder?: string): Promise<string> {
    const answer = await clack.text({ message: question, placeholder });
    if (clack.isCancel(answer)) throw new CancelledError();
    return answer.trim();
  }

  async confirm(question: string): Promise<boolean> {
    const answer = await clack.confirm({ message: question });
    if (clack.isCancel(answer)) throw new CancelledError();
    return answer;
  }

  show(title: string, body: string): void {
    clack.note(body, title);
  }

  step(message: string): void {
    clack.log.step(pc.dim(message));
  }

  info(message: string): void {
    clack.log.info(message);
  }

  warn(message: string): void {
    clack.log.warn(message);
  }

  success(message: string): void {
    clack.log.success(message);
  }
}

/** Answers questions from a list, in order. Used by tests and non-interactive runs. */
export class ScriptedHuman implements HumanIO {
  readonly transcript: string[] = [];

  constructor(private readonly answers: string[]) {}

  private next(question: string): string {
    const answer = this.answers.shift();
    if (answer === undefined) throw new Error(`No scripted answer left for: ${question}`);
    this.transcript.push(`? ${question} -> ${answer}`);
    return answer;
  }

  async choose(question: string, choices: Choice[]): Promise<string> {
    const answer = this.next(question);
    const match = choices.find((c) => c.value === answer || c.label === answer);
    if (!match) throw new Error(`Scripted answer "${answer}" is not one of: ${choices.map((c) => c.value).join(", ")}`);
    return match.value;
  }

  async ask(question: string): Promise<string> {
    return this.next(question);
  }

  async confirm(question: string): Promise<boolean> {
    return /^(y|yes|true)$/i.test(this.next(question));
  }

  show(title: string, body: string): void {
    this.transcript.push(`[${title}]\n${body}`);
  }

  step(message: string): void {
    this.transcript.push(`> ${message}`);
  }

  info(message: string): void {
    this.transcript.push(`i ${message}`);
  }

  warn(message: string): void {
    this.transcript.push(`! ${message}`);
  }

  success(message: string): void {
    this.transcript.push(`✓ ${message}`);
  }
}
