# leaky-app

A small, deliberately insecure app in the style Lovable and Bolt generate. It exists to demo and test Vibesecure. Don't deploy it.

**Database** (`supabase/migrations/`)

| Table, bucket or function | What's wrong |
|---|---|
| `posts` | RLS was never turned on |
| `notes` | RLS is on, but the policy is `using (true)` |
| `comments` | The insert policy doesn't check who the author is |
| `author_stats` | A view that skips RLS and shows everyone's email |
| `invoices` bucket | Any signed-in user can read everyone's invoices |
| `profiles.role` | Users can set their own role to `admin`, and `is_admin()` trusts it |
| `search_posts()` | Pastes the search text into SQL and runs it as security definer |
| `delete_user_notes()` | Security definer and never checks the caller: anyone can wipe anyone's notes |
| `todos`, `categories`, `avatars`, `is_admin()`, `post_count()` | Done right, to catch false alarms |

**Code**

| File | What's wrong |
|---|---|
| `supabase/functions/stripe-webhook/` | Trusts "payment succeeded" events without checking Stripe's signature |
| `supabase/functions/ask-ai/` | Calls a paid AI API with no login check and no rate limit, and `verify_jwt` is off |
| `src/components/CommentBody.tsx` | Renders comment HTML without sanitizing it (XSS) |
| `src/lib/openai.ts` | Puts an OpenAI key in a `VITE_` variable, which ships to the browser |
| `src/pages/Login.tsx` | Redirects to whatever `?next=` says (open redirect) |
| `src/pages/Search.tsx` | Pastes search text into a Supabase `.or()` filter |
| `src/lib/invite.ts` | Makes invite codes with `Math.random()` |

`SafeCommentBody` and `shuffle()` are done right, also to catch false alarms.

```bash
npx vibesecure scan examples/leaky-app
npx vibesecure fix examples/leaky-app
```
