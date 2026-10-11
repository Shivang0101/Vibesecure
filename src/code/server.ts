import { OWASP, type Finding } from "../scan/findings.js";
import { verifyJwtOff, type SupabaseConfig } from "./config.js";
import { codeFinding, matches, readExpression, type CodeIssue } from "./finding.js";
import { usesServiceKey } from "./rules.js";
import type { SourceFile } from "./source.js";

/** Services that cost money per call, or can be abused to spam people. */
const PAID_SERVICES: { name: string; pattern: RegExp }[] = [
  { name: "OpenAI", pattern: /api\.openai\.com|from\s+['"](?:npm:|jsr:|https:\/\/esm\.sh\/)?openai(?:@[^'"]*)?['"]|new\s+OpenAI\s*\(|@ai-sdk\/openai/ },
  { name: "Anthropic", pattern: /api\.anthropic\.com|@anthropic-ai\/sdk|new\s+Anthropic\s*\(|@ai-sdk\/anthropic/ },
  { name: "Google Gemini", pattern: /generativelanguage\.googleapis\.com|@google\/genai|@google\/generative-ai|@ai-sdk\/google/ },
  { name: "Lovable AI", pattern: /ai\.gateway\.lovable\.dev/ },
  { name: "OpenRouter", pattern: /openrouter\.ai\/api|@openrouter\/ai-sdk-provider/ },
  { name: "Groq", pattern: /api\.groq\.com|@ai-sdk\/groq|groq-sdk/ },
  { name: "Mistral", pattern: /api\.mistral\.ai|@ai-sdk\/mistral|@mistralai\// },
  { name: "DeepSeek", pattern: /api\.deepseek\.com|@ai-sdk\/deepseek/ },
  { name: "Perplexity", pattern: /api\.perplexity\.ai/ },
  { name: "Replicate", pattern: /api\.replicate\.com|from\s+['"](?:npm:)?replicate['"]/ },
  { name: "fal", pattern: /fal\.run|@fal-ai\// },
  { name: "Stability AI", pattern: /api\.stability\.ai/ },
  { name: "ElevenLabs", pattern: /api\.elevenlabs\.io|elevenlabs/ },
  { name: "Resend", pattern: /api\.resend\.com|from\s+['"](?:npm:|https:\/\/esm\.sh\/)?resend(?:@[^'"]*)?['"]/ },
  { name: "SendGrid", pattern: /api\.sendgrid\.com|@sendgrid\/mail/ },
  { name: "Postmark", pattern: /api\.postmarkapp\.com/ },
  { name: "Mailgun", pattern: /api\.mailgun\.net/ },
  { name: "Brevo", pattern: /api\.brevo\.com|api\.sendinblue\.com/ },
  { name: "Twilio", pattern: /api\.twilio\.com|from\s+['"](?:npm:)?twilio/ },
];

/** Signs that the code checks who is calling. */
const AUTH_CHECK =
  /\.auth\.getUser\s*\(|\.auth\.getClaims\s*\(|\bgetClaims\s*\(|\bjwtVerify\s*\(|\bverifyJwt\b|\bgetServerSession\s*\(|\bcurrentUser\s*\(\s*\)|\bawait\s+auth\s*\(\s*\)|\brequireAuth\b|\brequireUser\b|\bgetUserFromRequest\b/;
/** @supabase/server's withSupabase({ auth: 'user' }) rejects callers who aren't signed in. */
const WITH_SUPABASE_USER = /withSupabase\(\s*\{[^}]*\bauth\s*:\s*(?:['"]user['"]|\[[^\]]*['"]user['"])/;
/** withSupabase({ auth: 'secret' }) only lets in callers with your secret key: your own servers. */
const WITH_SUPABASE_SECRET = /withSupabase\(\s*\{[^}]*\bauth\s*:\s*(?:['"]secret['"]|\[[^\]]*['"]secret['"])/;
/** Reading an incoming secret header and comparing it (cron jobs, internal calls). */
const SHARED_SECRET_CHECK =
  /headers\.get\(\s*['"](?:authorization|x-[\w-]*(?:secret|cron|signature)[\w-]*)['"]\s*\)[\s\S]{0,300}?(?:===|!==|==|!=)/i;
/** Rate limiting written as code (matched with strings blanked, so error messages don't count). */
const RATE_LIMIT_CODE = /\b\w*(?:rate_?limit|ratelimit|throttl|limiter|slidingwindow|fixedwindow|tokenbucket)\w*\b/i;
/** Rate limiting through a package or a table. */
const RATE_LIMIT_USE = /@upstash\/ratelimit|\.from\(\s*['"]\w*rate_?limit\w*['"]|\.rpc\(\s*['"]\w*(?:rate_?limit|check_\w*limit)\w*['"]/i;

/** Events from Stripe, Razorpay, Lemon Squeezy, PayPal, Paddle and Cashfree that mean "they paid". */
const PAYMENT_EVENTS =
  /checkout\.session\.completed|payment_intent\.succeeded|charge\.succeeded|invoice\.(?:paid|payment_succeeded)|customer\.subscription\.(?:created|updated|deleted)|payment\.captured|order\.paid|subscription\.(?:charged|activated)|order_created|subscription_payment_success|PAYMENT\.CAPTURE\.COMPLETED|CHECKOUT\.ORDER\.(?:APPROVED|COMPLETED)|transaction\.completed|PAYMENT_SUCCESS_WEBHOOK/;
const SIGNATURE_CHECK =
  /constructEvent(?:Async)?\s*\(|createHmac|crypto\.subtle\.(?:verify|sign|importKey)|timingSafeEqual|validateWebhookSignature|svix|standardwebhooks|new\s+Webhook\s*\(|verifySignature|verifyWebhook|webhooks\.unmarshal\s*\(|verify-webhook-signature/;

/** Reading the claims out of a JWT without checking its signature. */
const JWT_DECODE = /\bjwtDecode\s*\(|\bjwt\.decode\s*\(|\bdecodeJwt\s*\(|\batob\(\s*[\w.?!]+\.split\(\s*['"]\.['"]\s*\)\s*\[\s*1\s*\]/;
const JWT_VERIFY = /\bjwtVerify\s*\(|\bjwt\.verify\s*\(|\.auth\.getUser\s*\(|\bgetClaims\s*\(|\bverifyJwt\b/;

/** Checks for one server file: who can call it, how often, and what it trusts. */
export function checkServerFile(file: SourceFile, config: SupabaseConfig | null): Finding[] {
  if (file.kind !== "server" || !/\.(ts|js|mjs|cjs)$/.test(file.path)) return [];
  const out: Finding[] = [];
  const add = (index: number, issue: CodeIssue) => {
    const finding = codeFinding(file, index, issue);
    if (finding) out.push(finding);
  };

  // Receives webhooks; "send-webhook" and the like send them instead.
  const webhookPath = /webhook/i.test(file.path) && !/(?:send|dispatch|notify|outgoing)[-_]?webhook/i.test(file.path);
  const webhook = webhookPath || PAYMENT_EVENTS.test(file.code) || /stripe-signature/i.test(file.code);
  const signed = SIGNATURE_CHECK.test(file.code);
  const paymentEvent = PAYMENT_EVENTS.exec(file.code);

  if (paymentEvent && !signed) {
    add(paymentEvent.index, {
      rule: "webhook-unverified-payment",
      severity: "critical",
      title: "This payment webhook doesn't check the signature, so anyone can send it a fake \"payment succeeded\" event.",
      detail: "Whoever finds the URL can unlock paid features, or mark orders paid, for free.",
      fix: "Verify every request first, e.g. for Stripe: stripe.webhooks.constructEventAsync(rawBody, req.headers.get('stripe-signature'), webhookSecret).",
      owasp: OWASP.integrity,
    });
  } else if (webhook && !signed) {
    add(firstIndex(file, /webhook/i), {
      rule: "webhook-unverified",
      severity: "medium",
      title: "This webhook doesn't check a signature, so anyone can send it fake events.",
      fix: "Check the signature header the sender provides (an HMAC of the body with your webhook secret) before trusting the request.",
      owasp: OWASP.integrity,
    });
  }

  const jwtOff = verifyJwtOff(config, file.functionName);
  // Supabase checks the JWT's signature before an edge function runs, unless verify_jwt is off.
  const gatewayVerifies = file.functionName !== undefined && !jwtOff;
  const decoded = JWT_DECODE.exec(file.code);
  if (decoded && !gatewayVerifies && !JWT_VERIFY.test(file.code)) {
    add(decoded.index, {
      rule: "jwt-not-verified",
      severity: "high",
      title: "Reads the user out of a login token without checking the token's signature.",
      detail: "Anyone can write a token that says they are any user, or an admin, and this code will believe it.",
      fix: "Verify it instead: supabase.auth.getUser(token), or jwtVerify() from jose with your project's JWKS.",
      owasp: OWASP.authentication,
    });
  }

  // Who can get in: signed-in users, or only callers holding a secret (your servers, signed webhooks).
  const userAuth = AUTH_CHECK.test(file.code) || WITH_SUPABASE_USER.test(file.code) || (decoded !== null && gatewayVerifies);
  const secretAuth = SHARED_SECRET_CHECK.test(file.code) || WITH_SUPABASE_SECRET.test(file.code) || signed;
  const authChecked = userAuth || secretAuth;
  const rateLimited = RATE_LIMIT_CODE.test(file.bare) || RATE_LIMIT_USE.test(file.code) || sends429(file);
  const paid = PAID_SERVICES.filter((s) => s.pattern.test(file.code));
  const serviceKey = usesServiceKey(file);
  const jwtNote =
    file.functionName === undefined
      ? "It's a public URL: anyone who finds it can call it."
      : jwtOff
        ? "verify_jwt is off for this function in supabase/config.toml, so callers don't even need your public key."
        : "Your public anon key is enough to call it, and that key is in your website for anyone to copy.";

  if (!webhook && (paid.length > 0 || serviceKey)) {
    const names = paid.map((s) => s.name).join(" and ");
    const where = paid.length > 0 ? firstIndex(file, paid[0]!.pattern) : firstIndex(file, /SERVICE_ROLE|SERVICE_KEY|SUPABASE_SECRET_KEY|sb_secret_/);
    if (!authChecked && paid.length > 0) {
      add(where, {
        rule: "function-no-auth-paid-api",
        severity: rateLimited ? "medium" : "high",
        title: rateLimited
          ? `Anyone can call this function and use your ${names} account (it has a rate limit, but no login check).`
          : `Anyone can call this function as often as they like and use your ${names} account (no login check, no rate limit).`,
        detail: `Bots can run up your bill or use it to spam people ("denial of wallet"). ${jwtNote}`,
        fix: "Check the caller with supabase.auth.getUser() and return 401 without a user, then limit calls per user (for example with @upstash/ratelimit or a counts table).",
        owasp: OWASP.insecureDesign,
      });
    } else if (!authChecked && serviceKey) {
      add(where, {
        rule: "function-no-auth-service-key",
        severity: "high",
        title: "This function uses your service key (full database access, no RLS) but never checks who is calling.",
        detail: jwtNote,
        fix: "Check the caller with supabase.auth.getUser() first, and only do what that user is allowed to do.",
        owasp: OWASP.authentication,
      });
    } else if (userAuth && paid.length > 0 && !rateLimited) {
      add(where, {
        rule: "function-no-rate-limit",
        severity: "medium",
        title: `Signed-in users can call this function as often as they like and run up your ${names} bill (no rate limit).`,
        detail: "One script with a free account can make thousands of calls.",
        fix: "Limit calls per user, e.g. with @upstash/ratelimit, or count recent calls in a table and return 429 above a limit.",
        owasp: OWASP.insecureDesign,
      });
    }
  }

  const cors = /Access-Control-Allow-Origin['"]?\s*[:,]\s*(?:(?:req|request)\.headers\.get\(\s*['"]origin['"]\s*\)|(?:req|request)\.headers\.origin|origin\b)/i.exec(file.code);
  if (cors && /Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true/i.test(file.code) && !/allowedOrigins|ALLOWED_ORIGINS|\.includes\(\s*origin\s*\)|origin\s*===/.test(file.code)) {
    add(cors.index, {
      rule: "cors-reflects-origin",
      severity: "medium",
      title: "Lets any website make logged-in requests here (CORS echoes back the Origin, with credentials).",
      detail: "A page on another site can call this endpoint with your visitor's cookies and read the answer.",
      fix: "Only echo origins from a fixed list of your own domains, or drop Access-Control-Allow-Credentials.",
      owasp: OWASP.misconfiguration,
    });
  }

  out.push(...checkSsrf(file));
  return out;
}

const URLISH = /url|uri|link|href|endpoint|webhook|callback|image|img|src|target|feed|site|domain|host/i;

/** The server fetches an address that came straight from the request. */
function checkSsrf(file: SourceFile): Finding[] {
  if (/allowed(?:Hosts|Domains|Origins|Urls)|allowlist|whitelist|\.hostname\s*(?:===|!==|==)|ALLOWED_/i.test(file.code)) {
    return [];
  }
  const tainted = new Set<string>();
  let bodyName: string | null = null;

  for (const m of matches(file.code, /\{([^{}]*)\}\s*=\s*await\s+(?:req|request)\.json\(\)/g)) {
    for (const part of m[1]!.split(",")) {
      const local = part.split("=")[0]!.split(":").pop()!.trim();
      if (/^\w+$/.test(local)) tainted.add(local);
    }
  }
  const whole = /\b(?:const|let|var)\s+(\w+)\s*=\s*await\s+(?:req|request)\.json\(\)/.exec(file.code);
  if (whole) bodyName = whole[1]!;
  for (const m of matches(file.code, /\b(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*searchParams\.get\(/g)) tainted.add(m[1]!);

  const out: Finding[] = [];
  for (const m of matches(file.code, /\bfetch\(\s*/g)) {
    const expr = readExpression(file.code, m.index + m[0].length);
    const name = /^`?\$?\{?\s*(\w+)(?:\.(\w+))?/.exec(expr);
    if (!name) continue;
    const [, first, property] = name;
    const fromRequest =
      (tainted.has(first!) && URLISH.test(first!)) || (bodyName !== null && first === bodyName && URLISH.test(property ?? ""));
    if (!fromRequest) continue;
    const finding = codeFinding(file, m.index, {
      rule: "ssrf",
      severity: "medium",
      title: `The server fetches an address taken straight from the request: fetch(${expr.slice(0, 40)}).`,
      detail: "Anyone can make your server call any URL, including internal addresses, and read the reply (server-side request forgery).",
      fix: "Parse it with new URL() and only allow https URLs on hosts you expect.",
      owasp: OWASP.ssrf,
    });
    if (finding) out.push(finding);
  }
  return out;
}

/**
 * A hand-rolled limit answers 429 itself. Lovable's AI template also returns
 * 429, but only to pass on the AI gateway's own 429 (`response.status === 429`).
 */
function sends429(file: SourceFile): boolean {
  const sent = file.bare.match(/status\s*:\s*429\b/g)?.length ?? 0;
  const passedOn = file.bare.match(/\.status\s*===?\s*429\b/g)?.length ?? 0;
  return sent > passedOn;
}

function firstIndex(file: SourceFile, pattern: RegExp): number {
  return Math.max(0, file.code.search(pattern));
}
