// Library entry point, for using Vibesecure from code instead of the CLI.
export { scanProject, prepareProject, scanPrepared, type ScanResult, type ScanOptions } from "./scan/index.js";
export { deriveFindings, type Finding, type Severity } from "./scan/findings.js";
export { verifyFix, type Verification } from "./fix/verify.js";
export { findLeakyPolicies, templateSql } from "./fix/templates.js";
export { checkIntent, type Intent, type Audience } from "./fix/intent.js";
export { runFixAgent, type AgentOutcome } from "./agent/loop.js";
export { AnthropicModel, type ModelClient } from "./agent/model.js";
