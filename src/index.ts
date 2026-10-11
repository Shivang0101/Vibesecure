// Library entry point, for using Vibesecure from code instead of the CLI.
export {
  scanProject,
  prepareProject,
  scanPrepared,
  scanCodeOnly,
  type ScanResult,
  type ScanOptions,
  type CodeOnlyResult,
} from "./scan/index.js";
export { deriveFindings, OWASP, type Finding, type Severity } from "./scan/findings.js";
export { measureEscalation, type Escalation } from "./scan/escalation.js";
export { readFunctions, functionFindings, type DatabaseFunction } from "./scan/functions.js";
export { runCodeChecks, type CodeReport } from "./code/index.js";
export { verifyFix, type Verification } from "./fix/verify.js";
export { findLeakyPolicies, templateSql } from "./fix/templates.js";
export { lockColumnsSql, verifyColumnLock } from "./fix/columns.js";
export { checkIntent, type Intent, type Audience } from "./fix/intent.js";
export { runFixAgent, type AgentOutcome } from "./agent/loop.js";
export { AnthropicModel, type ModelClient } from "./agent/model.js";
