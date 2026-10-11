import { describe, expect, it } from "vitest";
import { runCodeChecks } from "../src/code/index.js";
import { blankJs } from "../src/code/source.js";
import type { Finding } from "../src/scan/findings.js";
import { EXAMPLE_APP, makeProject } from "./helpers.js";

// Fake keys are put together at runtime so this file never contains anything
// that looks like a real secret to GitHub's push protection.
const jwt = (payload: object) =>
  [{ alg: "HS256", typ: "JWT" }, payload].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".") +
  ".c2lnbmF0dXJlLXNpZ25hdHVyZQ";
const SERVICE_ROLE_JWT = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1700000000 });
const ANON_JWT = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1700000000 });
const OPENAI_KEY = ["sk", "proj", "a".repeat(40)].join("-");
const STRIPE_LIVE_KEY = ["sk", "live", "b".repeat(24)].join("_");
const SUPABASE_SECRET_KEY = ["sb", "secret", "c".repeat(30)].join("_");

/** Runs the checks on a throwaway project and returns "rule file:line" per finding. */
function check(files: Record<string, string>): { found: string[]; findings: Finding[] } {
  const { findings } = runCodeChecks(makeProject(files));
  return { found: findings.map((f) => `${f.rule} ${f.label}`), findings };
}

function rules(files: Record<string, string>): string[] {
  return check(files).found.map((f) => f.split(" ")[0]!);
}

describe("the example app's code", () => {
  const { files, findings } = runCodeChecks(EXAMPLE_APP);
  const found = findings.map((f) => `${f.severity} ${f.rule} ${f.label}`).sort();

  it("finds each planted problem", () => {
    expect(found).toEqual([
      "critical webhook-unverified-payment supabase/functions/stripe-webhook/index.ts:13",
      "high function-no-auth-paid-api supabase/functions/ask-ai/index.ts:12",
      "high secret-in-client-env src/lib/openai.ts:3",
      "high xss-dangerous-html src/components/CommentBody.tsx:5",
      "medium insecure-random src/lib/invite.ts:3",
      "medium open-redirect src/pages/Login.tsx:10",
      "medium postgrest-filter-injection src/pages/Search.tsx:11",
    ]);
    expect(files).toBeGreaterThan(8);
  });

  it("ignores the migrations folder", () => {
    expect(findings.some((f) => f.location?.file.includes("migrations"))).toBe(false);
  });
});

describe("cross-site scripting", () => {
  it("flags dangerouslySetInnerHTML with a variable, not a literal or sanitized HTML", () => {
    expect(
      check({
        "src/Post.tsx": [
          "export const A = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;",
          "export const B = ({ html }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;",
          'export const C = () => <style dangerouslySetInnerHTML={{ __html: ".a { color: red }" }} />;',
        ].join("\n"),
      }).found,
    ).toEqual(["xss-dangerous-html src/Post.tsx:1"]);
  });

  it("leaves shadcn/ui's chart component alone", () => {
    expect(rules({ "src/components/ui/chart.tsx": "<style dangerouslySetInnerHTML={{ __html: css }} />" })).toEqual([]);
  });

  it("rates JSON in a script tag low, and not at all when < is escaped", () => {
    const { findings } = check({
      "src/Seo.tsx": [
        '<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />',
        '<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, "\\\\u003c") }} />',
      ].join("\n"),
    });
    expect(findings.map((f) => [f.rule, f.severity, f.location?.line])).toEqual([["xss-json-in-html", "low", 1]]);
  });

  it("flags innerHTML and document.write with values, but not clearing an element", () => {
    expect(
      check({
        "src/widget.ts": ['el.innerHTML = "";', "el.innerHTML = message;", "document.write(banner);"].join("\n"),
      }).found,
    ).toEqual(["xss-dom-html src/widget.ts:2", "xss-dom-html src/widget.ts:3"]);
  });

  it("flags react-markdown with rehype-raw unless rehype-sanitize is there too", () => {
    const raw = 'import rehypeRaw from "rehype-raw";\n<ReactMarkdown rehypePlugins={[rehypeRaw]}>{text}</ReactMarkdown>';
    expect(rules({ "src/Chat.tsx": raw })).toEqual(["xss-markdown-raw-html"]);
    expect(rules({ "src/Chat.tsx": `import rehypeSanitize from "rehype-sanitize";\n${raw}` })).toEqual([]);
  });
});

describe("secrets", () => {
  it("flags a service_role key in browser code, but not the anon key", () => {
    const { findings } = check({
      "src/integrations/supabase/client.ts": `const anon = "${ANON_JWT}";\nconst admin = "${SERVICE_ROLE_JWT}";`,
    });
    expect(findings.map((f) => [f.rule, f.severity, f.location?.line])).toEqual([["secret-in-code", "critical", 2]]);
    expect(findings[0]!.title).toBe("A Supabase service_role key is in code that ships to the browser.");
  });

  it("rates a key in server code one level lower, and never prints it", () => {
    const { findings } = check({ "supabase/functions/admin/index.ts": `const key = "${SUPABASE_SECRET_KEY}";` });
    const secret = findings.filter((f) => f.rule === "secret-in-code");
    expect(secret.map((f) => f.severity)).toEqual(["high"]);
    expect(secret[0]!.snippet).not.toContain(SUPABASE_SECRET_KEY);
    expect(secret[0]!.snippet).toContain("sb_secret_…");
  });

  it("flags a real key in a VITE_ variable once, and hides .env values", () => {
    const { findings } = check({
      ".env": `VITE_SUPABASE_URL=https://abc.supabase.co\nVITE_OPENAI_API_KEY=${OPENAI_KEY}\n`,
      ".gitignore": ".env\n",
      "src/ai.ts": "const key = import.meta.env.VITE_OPENAI_API_KEY;",
    });
    expect(findings.map((f) => [f.rule, f.severity, f.label])).toEqual([["secret-in-client-env", "critical", ".env:2"]]);
    expect(findings[0]!.title).toContain("holds an OpenAI API key");
    expect(findings[0]!.snippet).toBe("VITE_OPENAI_API_KEY=…");
  });

  it("flags a secret-sounding VITE_ variable the code reads, but not the publishable key", () => {
    expect(
      check({
        "src/client.ts":
          "createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);\n" +
          "const stripe = import.meta.env.VITE_STRIPE_SECRET_KEY;",
      }).found,
    ).toEqual(["secret-in-client-env src/client.ts:2"]);
  });

  it("warns about a .env with secrets that git would commit", () => {
    const env = `STRIPE_SECRET_KEY=${STRIPE_LIVE_KEY}\n`;
    expect(rules({ ".env": env })).toEqual(["env-file-not-ignored"]);
    expect(rules({ ".env": env, ".gitignore": "node_modules\n*.local\n.env\n" })).toEqual([]);
    expect(rules({ ".env.example": "STRIPE_SECRET_KEY=your-key-here\n" })).toEqual([]);
  });
});

describe("projects inside a bigger repo", () => {
  it("finds edge functions and their config.toml in a subfolder", () => {
    const { findings } = check({
      "apps/web/supabase/functions/ask/index.ts": 'import OpenAI from "npm:openai";\nDeno.serve(async () => new Response("ok"));',
      "apps/web/supabase/config.toml": "[functions.ask]\nverify_jwt = false\n",
    });
    expect(findings.map((f) => f.rule)).toEqual(["function-no-auth-paid-api"]);
    expect(findings[0]!.detail).toContain("verify_jwt is off");
  });

  it("follows .gitignore files in subfolders and anchored patterns, like git", () => {
    const env = `STRIPE_SECRET_KEY=${STRIPE_LIVE_KEY}\n`;
    expect(rules({ "apps/web/.env": env, "apps/web/.gitignore": ".env\n" })).toEqual([]);
    expect(rules({ "apps/web/.env.local": env, ".gitignore": "**/.env*\n" })).toEqual([]);
    expect(rules({ "apps/web/.env": env, ".gitignore": "/.env\n" })).toEqual(["env-file-not-ignored"]);
  });
});

describe("server functions: login, rate limits and webhooks", () => {
  const lovableAi = (extra = "") => `
    Deno.serve(async (req) => {
      ${extra}
      const { prompt } = await req.json();
      const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", { method: "POST" });
      if (response.status === 429) return new Response("Rate limited", { status: 429 });
      return new Response(await response.text());
    });`;
  const login = `
      const supabase = createClient(url, anonKey, { global: { headers: { Authorization: req.headers.get("Authorization")! } } });
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return new Response("Unauthorized", { status: 401 });`;

  it("flags an AI function with no login and no limit, even though it passes on the gateway's 429", () => {
    const { findings } = check({ "supabase/functions/ask/index.ts": lovableAi() });
    expect(findings.map((f) => [f.rule, f.severity])).toEqual([["function-no-auth-paid-api", "high"]]);
    expect(findings[0]!.title).toContain("Lovable AI");
  });

  it("asks for a rate limit when there is a login but no limit", () => {
    expect(rules({ "supabase/functions/ask/index.ts": lovableAi(login) })).toEqual(["function-no-rate-limit"]);
  });

  it("accepts a login plus a limit, whether a library or a hand-made 429", () => {
    const upstash = `import { Ratelimit } from "npm:@upstash/ratelimit";\n${lovableAi(`${login}\nconst { success } = await ratelimit.limit(user.id);`)}`;
    const counted = lovableAi(`${login}
      const { count } = await supabase.from("ai_calls").select("*", { count: "exact", head: true }).eq("user_id", user.id);
      if ((count ?? 0) > 50) return new Response("Too many requests", { status: 429 });`);
    expect(rules({ "supabase/functions/ask/index.ts": upstash })).toEqual([]);
    expect(rules({ "supabase/functions/ask/index.ts": counted })).toEqual([]);
  });

  it("mentions verify_jwt = false from config.toml", () => {
    const { findings } = check({
      "supabase/functions/ask/index.ts": lovableAi(),
      "supabase/config.toml": '[functions.ask]\nverify_jwt = false # public\n',
    });
    expect(findings[0]!.detail).toContain("verify_jwt is off");
  });

  it("flags the service key used without checking the caller, but not a cron job with a shared secret", () => {
    const admin = 'const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);';
    expect(rules({ "supabase/functions/wipe/index.ts": `${admin}\nDeno.serve(async () => { await admin.from("t").delete(); });` })).toEqual([
      "function-no-auth-service-key",
    ]);
    const cron = `${admin}\nDeno.serve(async (req) => {\n  if (req.headers.get("x-cron-secret") !== Deno.env.get("CRON_SECRET")) return new Response("no", { status: 401 });\n});`;
    expect(rules({ "supabase/functions/nightly/index.ts": cron })).toEqual([]);
  });

  it("understands withSupabase() from @supabase/server", () => {
    const fn = (auth: string) => `
      import OpenAI from "npm:openai";
      export default { fetch: withSupabase({ auth: ${auth} }, async (req) => new Response("ok")) };`;
    expect(rules({ "supabase/functions/ai/index.ts": fn("'user'") })).toEqual(["function-no-rate-limit"]);
    expect(rules({ "supabase/functions/ai/index.ts": fn("['user', 'secret']") })).toEqual(["function-no-rate-limit"]);
    expect(rules({ "supabase/functions/ai/index.ts": fn("'secret'") })).toEqual([]);
    expect(rules({ "supabase/functions/ai/index.ts": fn("'none'") })).toEqual(["function-no-auth-paid-api"]);
  });

  it("treats a verified Supabase auth hook as checked, even though it sends email", () => {
    const hook = `
      import { Webhook } from "npm:standardwebhooks@1";
      import { Resend } from "npm:resend@4";
      Deno.serve(async (req) => {
        const wh = new Webhook(Deno.env.get("SEND_EMAIL_HOOK_SECRET")!);
        const { user } = wh.verify(await req.text(), Object.fromEntries(req.headers));
      });`;
    expect(rules({ "supabase/functions/send-email/index.ts": hook })).toEqual([]);
  });

  it("doesn't ask a function that sends webhooks to verify signatures", () => {
    expect(rules({ "supabase/functions/send-webhook/index.ts": "await fetch(Deno.env.get('HOOK_URL')!, { method: 'POST' });" })).toEqual([]);
  });

  it("only checks tests for secrets, since they never ship", () => {
    const { findings } = check({
      "supabase/functions/tests/utils.ts": `const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const key = "${OPENAI_KEY}";`,
      "src/components/Post.test.tsx": "render(<div dangerouslySetInnerHTML={{ __html: html }} />);",
    });
    expect(findings.map((f) => [f.rule, f.severity])).toEqual([["secret-in-code", "high"]]);
  });

  it("flags a payment webhook without a signature check, critical", () => {
    const unsigned = 'Deno.serve(async (req) => { const event = await req.json(); if (event.type === "checkout.session.completed") {} });';
    const signed =
      'Deno.serve(async (req) => { const event = await stripe.webhooks.constructEventAsync(await req.text(), req.headers.get("stripe-signature")!, secret); if (event.type === "checkout.session.completed") {} });';
    expect(check({ "supabase/functions/stripe-webhook/index.ts": unsigned }).findings.map((f) => [f.rule, f.severity])).toEqual([
      ["webhook-unverified-payment", "critical"],
    ]);
    expect(rules({ "supabase/functions/stripe-webhook/index.ts": signed })).toEqual([]);
  });

  it("flags reading a JWT without verifying it, unless Supabase verified it first", () => {
    const decode = 'const claims = JSON.parse(atob(token.split(".")[1]));';
    expect(rules({ "api/me.ts": decode })).toEqual(["jwt-not-verified"]);
    expect(rules({ "supabase/functions/me/index.ts": decode })).toEqual([]);
    expect(rules({ "supabase/functions/me/index.ts": decode, "supabase/config.toml": "[functions.me]\nverify_jwt = false\n" })).toEqual([
      "jwt-not-verified",
    ]);
  });

  it("flags fetching a URL straight from the request (SSRF)", () => {
    expect(rules({ "supabase/functions/preview/index.ts": "const { url } = await req.json();\nconst page = await fetch(url);" })).toEqual(["ssrf"]);
    expect(rules({ "supabase/functions/preview/index.ts": "const { url } = await req.json();\nif (!ALLOWED_HOSTS.includes(new URL(url).hostname)) throw 1;\nawait fetch(url);" })).toEqual([]);
  });

  it("flags CORS that echoes the origin with credentials", () => {
    const cors = 'res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\nres.setHeader("Access-Control-Allow-Credentials", "true");';
    expect(rules({ "api/data.ts": cors })).toEqual(["cors-reflects-origin"]);
  });
});

describe("injection", () => {
  it("flags search text pasted into .or(), but not ids", () => {
    expect(
      check({
        "src/Search.tsx": [
          "supabase.from('posts').select().or(`title.ilike.%${query}%,body.ilike.%${query}%`);",
          "supabase.from('messages').select().or(`sender_id.eq.${user?.id},receiver_id.eq.${otherUserId}`);",
        ].join("\n"),
      }).found,
    ).toEqual(["postgrest-filter-injection src/Search.tsx:1"]);
  });

  it("rates .or() injection high in server code that uses the service key", () => {
    const { findings } = check({
      "supabase/functions/search/index.ts": 'const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);\nconst { q } = await req.json();\nawait admin.from("posts").select().or(`title.eq.${q}`);\nawait supabase.auth.getUser();',
    });
    expect(findings.map((f) => [f.rule, f.severity])).toEqual([["postgrest-filter-injection", "high"]]);
  });

  it("flags SQL and shell commands built from variables", () => {
    expect(
      rules({
        "server/db.ts": [
          "await client.query(`select * from users where email = '${email}'`);",
          "await client.query('select * from users where email = $1', [email]);",
          "await prisma.$queryRawUnsafe(`select * from users where id = ${id}`);",
          "exec(`convert ${file} out.png`);",
        ].join("\n"),
      }),
    ).toEqual(["sql-injection", "sql-injection", "command-injection"]);
  });

  it("flags eval with a variable, not a constant", () => {
    expect(check({ "src/calc.ts": 'eval(input);\neval("1 + 1");\nnew Function("return this")();' }).found).toEqual([
      "code-injection-eval src/calc.ts:1",
    ]);
  });
});

describe("other app mistakes", () => {
  it("flags an open redirect, but not one that checks the path", () => {
    const login = 'const next = params.get("next") ?? "/";\nwindow.location.href = next;';
    expect(rules({ "src/pages/Login.tsx": login })).toEqual(["open-redirect"]);
    expect(rules({ "src/pages/Login.tsx": `${login}\nif (!next.startsWith("/")) return;` })).toEqual([]);
  });

  it("flags Math.random() for codes and tokens, not for shuffling or colors", () => {
    expect(
      check({
        "src/lib/util.ts": [
          "const resetToken = Math.random().toString(36);",
          "function generateApiKey() {",
          "  return Math.random().toString(36);",
          "}",
          "const shuffled = items.sort(() => Math.random() - 0.5);",
          "const color = colors[Math.floor(Math.random() * colors.length)];",
        ].join("\n"),
      }).found,
    ).toEqual(["insecure-random src/lib/util.ts:1", "insecure-random src/lib/util.ts:3"]);
  });

  it("flags admin or paid status read from localStorage, not UI settings", () => {
    expect(
      check({
        "src/hooks/useAdmin.ts": 'const theme = localStorage.getItem("theme");\nconst isAdmin = localStorage.getItem("isAdmin") === "true";',
      }).found,
    ).toEqual(["client-trusts-storage src/hooks/useAdmin.ts:2"]);
  });

  it("reads risky auth settings from supabase/config.toml", () => {
    expect(
      rules({
        "supabase/config.toml": [
          "[auth]",
          "minimum_password_length = 6",
          "enable_anonymous_sign_ins = true",
          "[auth.rate_limit]",
          "sign_in_sign_ups = 1000",
        ].join("\n"),
      }).sort(),
    ).toEqual(["auth-anonymous-sign-ins", "auth-rate-limit-raised", "auth-weak-passwords"]);
  });

  it("stays quiet when a line says vibesecure-ignore", () => {
    expect(
      rules({
        "src/Post.tsx": [
          "// vibesecure-ignore: html comes from our own CMS",
          "<div dangerouslySetInnerHTML={{ __html: html }} />",
          "<div dangerouslySetInnerHTML={{ __html: html }} /> {/* vibesecure-ignore */}",
        ].join("\n"),
      }),
    ).toEqual([]);
  });

  it("doesn't look inside comments", () => {
    expect(rules({ "src/Post.tsx": "// el.innerHTML = userInput;\n/* eval(code); */" })).toEqual([]);
  });
});

describe("blankJs", () => {
  it("keeps positions and lines while blanking comments, and string contents in `bare`", () => {
    const text = 'const a = "rate limit"; // note\nconst b = `x`; /* c */ const c = 1;';
    const { code, bare } = blankJs(text);
    expect(code).toHaveLength(text.length);
    expect(bare).toHaveLength(text.length);
    expect(code.split("\n")).toHaveLength(2);
    expect(code).toContain('"rate limit"');
    expect(code).not.toContain("note");
    expect(bare).not.toContain("rate limit");
    expect(bare).toContain("const c = 1;");
  });

  it("isn't thrown off by apostrophes in JSX text or regex literals", () => {
    const text = "<p>Don't panic</p>;\nconst re = /'/g;\nconst x = eval(input);";
    const { code } = blankJs(text);
    expect(code.split("\n")[2]).toBe("const x = eval(input);");
  });
});
