import { OWASP, type Finding } from "../scan/findings.js";
import { codeFinding, isLiteral, isSanitized, matches, readExpression, type CodeIssue } from "./finding.js";
import type { SourceFile } from "./source.js";

/** Checks that look at one file at a time. */
type FileCheck = (file: SourceFile) => Finding[];

const XSS_DETAIL =
  "If this HTML can contain anything a user typed (or an AI wrote), it can run scripts in other people's browsers and take over their accounts.";

/** React escapes text, but dangerouslySetInnerHTML turns that off. */
const dangerousHtml: FileCheck = (file) => {
  if (!isJsx(file) || isUiLibrary(file)) return [];
  const out: Finding[] = [];
  for (const m of matches(file.code, /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*/g)) {
    const expr = readExpression(file.code, m.index + m[0].length);
    if (isLiteral(expr) || isSanitized(expr)) continue;
    if (/^JSON\.stringify\(/.test(expr)) {
      // JSON-LD and similar: safe for fixed data, but JSON.stringify doesn't escape </script>.
      if (/\.replace\(/.test(expr)) continue;
      push(out, file, m.index, {
        rule: "xss-json-in-html",
        severity: "low",
        title: "Puts JSON.stringify() output into HTML, which doesn't escape </script>.",
        detail: "Fine for fixed data. If any value comes from users (a product name, a post title), it can close the tag and run scripts.",
        fix: "Escape < in the JSON: JSON.stringify(data).replace(/</g, '\\u003c').",
        owasp: OWASP.injection,
      });
      continue;
    }
    push(out, file, m.index, {
      rule: "xss-dangerous-html",
      severity: "high",
      title: `Renders HTML without sanitizing it (cross-site scripting): __html: ${short(expr)}`,
      detail: XSS_DETAIL,
      fix: "Sanitize it first with DOMPurify: __html: DOMPurify.sanitize(html). Or render it as plain text.",
      owasp: OWASP.injection,
    });
  }
  return out;
};

/** innerHTML, outerHTML, insertAdjacentHTML and document.write with a value that isn't a fixed string. */
const domHtmlSinks: FileCheck = (file) => {
  if (!isCode(file) || file.kind === "server") return [];
  const out: Finding[] = [];
  const sinks: [RegExp, boolean][] = [
    [/\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*/g, false],
    [/\binsertAdjacentHTML\s*\(\s*[^,]+,\s*/g, true],
    [/\bdocument\.write(?:ln)?\s*\(\s*/g, true],
  ];
  for (const [pattern, inCall] of sinks) {
    for (const m of matches(file.code, pattern)) {
      const expr = readExpression(file.code, m.index + m[0].length, inCall);
      if (expr === "" || isLiteral(expr) || isSanitized(expr)) continue;
      push(out, file, m.index, {
        rule: "xss-dom-html",
        severity: "high",
        title: `Puts unsanitized HTML into the page (cross-site scripting): ${short(expr)}`,
        detail: XSS_DETAIL,
        fix: "Use textContent for text, or sanitize with DOMPurify.sanitize() before inserting HTML.",
        owasp: OWASP.injection,
      });
    }
  }
  return out;
};

/** react-markdown with rehype-raw renders any HTML inside the markdown. */
const markdownRawHtml: FileCheck = (file) => {
  if (!isCode(file) || file.kind === "server") return [];
  if (/rehype-?sanitize|rehypeSanitize/.test(file.code)) return [];
  const m = /\brehypeRaw\b|['"]rehype-raw['"]/.exec(file.code);
  if (!m) return [];
  return single(file, m.index, {
    rule: "xss-markdown-raw-html",
    severity: "high",
    title: "Markdown is rendered with raw HTML switched on (rehype-raw) and no sanitizer.",
    detail: "Chat messages, AI answers or comments rendered here can carry <script>-like HTML. " + XSS_DETAIL,
    fix: "Add rehype-sanitize after rehype-raw (rehypePlugins={[rehypeRaw, rehypeSanitize]}), or drop rehype-raw.",
    owasp: OWASP.injection,
  });
};

/** eval and new Function run a string as code. */
const evalCode: FileCheck = (file) => {
  if (!isCode(file)) return [];
  const out: Finding[] = [];
  for (const m of matches(file.code, /(?<![\w.$])eval\s*\(\s*|\bnew\s+Function\s*\(\s*/g)) {
    const expr = readExpression(file.code, m.index + m[0].length, false);
    if (expr === "" || isLiteral(expr)) continue;
    push(out, file, m.index, {
      rule: "code-injection-eval",
      severity: "high",
      title: `Runs a string as code with ${m[0].includes("Function") ? "new Function()" : "eval()"}.`,
      detail: "If any part of that string comes from a user, they can run their own code in your app.",
      fix: "Parse data with JSON.parse() and look up behaviour in an object instead of building code as text.",
      owasp: OWASP.injection,
    });
  }
  return out;
};

const REDIRECT_PARAMS =
  "redirect|redirect_to|redirectTo|redirect_url|redirectUrl|next|returnTo|return_to|returnUrl|return_url|callbackUrl|callback|continue|goto";

/** Sending people to an address taken from the URL, like /login?next=https://evil.example. */
const openRedirect: FileCheck = (file) => {
  if (!isCode(file) || file.kind !== "client") return [];
  if (/startsWith\(\s*['"]\/['"]\s*\)|new URL\(|isSafeRedirect|isValidRedirect|allowedRedirects|sameOrigin|\.origin\s*===/.test(file.code)) {
    return [];
  }
  const fromUrl = new Set<string>();
  const assign = new RegExp(String.raw`\b(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*?\.get\(\s*['"](?:${REDIRECT_PARAMS})['"]\s*\)`, "g");
  for (const m of matches(file.code, assign)) fromUrl.add(m[1]!);

  const inline = String.raw`[^;\n]*\.get\(\s*['"](?:${REDIRECT_PARAMS})['"]\s*\)`;
  const names = fromUrl.size > 0 ? [...fromUrl].join("|") : "(?!)";
  const sink = new RegExp(
    String.raw`(?:(?:window\.)?location(?:\.href)?\s*=(?!=)\s*|location\.(?:assign|replace)\(\s*|window\.open\(\s*)(?:(?:${names})\b|${inline})`,
    "g",
  );
  const out: Finding[] = [];
  for (const m of matches(file.code, sink)) {
    push(out, file, m.index, {
      rule: "open-redirect",
      severity: "medium",
      title: "Sends people to whatever address is in the URL's redirect parameter (open redirect).",
      detail: "Attackers can share a link to your real site that bounces visitors to a fake login page.",
      fix: "Only follow paths on your own site: if (!next.startsWith('/') || next.startsWith('//')) next = '/'.",
      owasp: OWASP.accessControl,
    });
  }
  return out;
};

const SECRET_VALUE_NAME =
  /(token|secret|passw|passcode|otp|nonce|salt|api_?key|session_?(?:id|key|token)|(?:invite|join|room|share|access|reset|verif\w*|confirm\w*|coupon|promo|referral|redeem|gift)_?code|coupon|voucher)/i;

/** Math.random() is predictable, so it must not make tokens, codes or passwords. */
const insecureRandom: FileCheck = (file) => {
  if (!isCode(file)) return [];
  const out: Finding[] = [];
  for (const m of matches(file.code, /Math\.random\(\)/g)) {
    if (!namesNear(file.code, m.index).some((name) => SECRET_VALUE_NAME.test(name))) continue;
    push(out, file, m.index, {
      rule: "insecure-random",
      severity: "medium",
      title: "Makes a secret value (token, code or password) with Math.random(), which can be predicted.",
      fix: "Use crypto.randomUUID() or crypto.getRandomValues() instead.",
      owasp: OWASP.crypto,
    });
  }
  return out;
};

/** The variable or property being assigned on this line, and the function it's in. */
function namesNear(code: string, index: number): string[] {
  const lineStart = code.lastIndexOf("\n", index) + 1;
  const names = [...code.slice(lineStart, index).matchAll(/(\w+)\s*(?::|=(?![=>]))/g)].map((m) => m[1]!);
  const before = code.slice(Math.max(0, index - 600), index);
  const functions = [...before.matchAll(/function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>/g)];
  // The nearest function that hasn't closed yet: more { than } since it started,
  // or an arrow function whose expression body is still going.
  const open = functions.reverse().find((fn) => {
    const body = before.slice(fn.index! + fn[0].length);
    const depth = (body.match(/\{/g)?.length ?? 0) - (body.match(/\}/g)?.length ?? 0);
    return depth > 0 || (fn[2] !== undefined && !/[;{}]/.test(body));
  });
  if (open) names.push((open[1] ?? open[2])!);
  return names;
}

/** supabase-js .or() takes one filter string; pasting user input into it lets them add conditions. */
const filterInjection: FileCheck = (file) => {
  if (!isCode(file)) return [];
  const out: Finding[] = [];
  const serviceKey = usesServiceKey(file);
  for (const m of matches(file.code, /\.or\(\s*`([^`]*\$\{[^`]*)`/g)) {
    const pasted = [...m[1]!.matchAll(/\$\{([^}]*)\}/g)].map((p) => p[1]!.replace(/[\s?!]/g, ""));
    // `sender_id.eq.${user.id}` is the usual "my rows" filter: ids aren't typed by people.
    if (pasted.every((p) => /(?:\.id|Id|_id|ID)$/.test(p))) continue;
    push(out, file, m.index, {
      rule: "postgrest-filter-injection",
      severity: file.kind === "server" && serviceKey ? "high" : "medium",
      title: "Pastes a variable into a Supabase .or() filter string (filter injection).",
      detail:
        "Text with commas or brackets, like `x,user_id.neq.0`, adds its own conditions to the query. " +
        (file.kind === "server" && serviceKey
          ? "This code uses the service key, so RLS won't stop it from returning other users' rows."
          : "RLS still applies, but the query can return rows your page never meant to show."),
      fix: "Strip or escape , ( ) . from the input first, or use separate .ilike()/.eq() calls instead of an .or() string.",
      owasp: OWASP.injection,
    });
  }
  return out;
};

/** Raw SQL built by pasting values into the query text. */
const sqlInjection: FileCheck = (file) => {
  if (!isCode(file)) return [];
  const out: Finding[] = [];
  const patterns = [
    /\.(?:query|execute|raw|unsafe|queryObject|queryArray)\s*\(\s*`[^`]*\$\{/g,
    /\.(?:query|execute|raw)\s*\(\s*(['"])[^'"\n]*\1\s*\+/g,
    /\bsql\.unsafe\s*\(/g,
    /\$(?:query|execute)RawUnsafe\s*\(\s*(?:`[^`]*\$\{|(['"])[^'"\n]*\1\s*\+)/g,
  ];
  for (const pattern of patterns) {
    for (const m of matches(file.code, pattern)) {
      push(out, file, m.index, {
        rule: "sql-injection",
        severity: "high",
        title: "Builds a SQL query by pasting values into its text (SQL injection).",
        detail: "Input like `' or 1=1 --` changes what the query does: it can read or delete any data the connection can.",
        fix: "Pass values as parameters: query('select * from t where id = $1', [id]), or use the sql`...` tagged template.",
        owasp: OWASP.injection,
      });
    }
  }
  return out;
};

/** Shell commands built from variables. */
const commandInjection: FileCheck = (file) => {
  if (!isCode(file) || file.kind === "client") return [];
  const out: Finding[] = [];
  const patterns = [
    /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/g,
    /\b(?:exec|execSync)\s*\(\s*[^)'"`\n]*\+/g,
    /new\s+Deno\.Command\(\s*['"](?:sh|bash|zsh|cmd|powershell)['"]/g,
  ];
  for (const pattern of patterns) {
    for (const m of matches(file.code, pattern)) {
      push(out, file, m.index, {
        rule: "command-injection",
        severity: "high",
        title: "Runs a shell command built from variables (command injection).",
        detail: "Input containing ; or && runs extra commands on your server.",
        fix: "Call the program directly with an argument list (execFile / Deno.Command with args) and never through a shell.",
        owasp: OWASP.injection,
      });
    }
  }
  return out;
};

/** Admin or paid status decided in the browser, where anyone can change it. */
const clientTrust: FileCheck = (file) => {
  if (!isCode(file) || file.kind !== "client") return [];
  const out: Finding[] = [];
  const storage =
    /\b(?:localStorage|sessionStorage)\.getItem\(\s*['"`](\w*(?:admin|role|premium|is_?paid|paid_?user|is_?pro|pro_?user|subscribed|unlocked|is_?vip)\w*)['"`]/gi;
  for (const m of matches(file.code, storage)) {
    push(out, file, m.index, {
      rule: "client-trusts-storage",
      severity: "medium",
      title: `Reads "${m[1]}" from browser storage, which anyone can change in dev tools.`,
      detail: "If it unlocks admin pages or paid features, people can give themselves access.",
      fix: "Read roles and plans from your database (protected by RLS), and enforce them there or on the server.",
      owasp: OWASP.insecureDesign,
    });
  }
  const adminEmail = /\b(?:user|currentUser|authUser|session\??\.user)\??\.email\s*={2,3}\s*['"][^'"@\s]+@[^'"\s]+['"]/g;
  for (const m of matches(file.code, adminEmail)) {
    push(out, file, m.index, {
      rule: "client-admin-check",
      severity: "low",
      title: "Decides who is an admin by comparing an email address in the browser.",
      detail: "That only hides buttons. Anyone can call your API directly, so the database has to enforce admin rights too.",
      fix: "Keep admins in a table (e.g. user_roles) and check it in RLS policies through a security definer function.",
      owasp: OWASP.accessControl,
    });
  }
  return out;
};

export const FILE_CHECKS: FileCheck[] = [
  dangerousHtml,
  domHtmlSinks,
  markdownRawHtml,
  evalCode,
  openRedirect,
  insecureRandom,
  filterInjection,
  sqlInjection,
  commandInjection,
  clientTrust,
];

export function usesServiceKey(file: SourceFile): boolean {
  return /SERVICE_ROLE|SERVICE_KEY|SUPABASE_SECRET_KEY|sb_secret_/.test(file.code);
}

function isCode(file: SourceFile): boolean {
  return /\.(tsx?|jsx?|mjs|cjs|vue|svelte|astro)$/.test(file.path);
}

function isJsx(file: SourceFile): boolean {
  return /\.(tsx|jsx|js|astro)$/.test(file.path);
}

/** shadcn/ui primitives (chart.tsx uses dangerouslySetInnerHTML for its own CSS). */
function isUiLibrary(file: SourceFile): boolean {
  return /(^|\/)components\/ui\//.test(file.path);
}

function short(expr: string): string {
  const flat = expr.replace(/\s+/g, " ");
  return flat.length > 60 ? `${flat.slice(0, 57)}...` : flat;
}

function push(out: Finding[], file: SourceFile, index: number, issue: CodeIssue): void {
  const finding = codeFinding(file, index, issue);
  if (finding) out.push(finding);
}

function single(file: SourceFile, index: number, issue: CodeIssue): Finding[] {
  const finding = codeFinding(file, index, issue);
  return finding ? [finding] : [];
}
