# leaky-app

A small, deliberately insecure app in the style Lovable and Bolt generate. It exists to demo and test Vibesecure. Don't deploy it.

| Table or bucket | What's wrong |
|---|---|
| `posts` | RLS was never turned on |
| `notes` | RLS is on, but the policy is `using (true)` |
| `comments` | The insert policy doesn't check who the author is |
| `author_stats` | A view that skips RLS and shows everyone's email |
| `invoices` bucket | Any signed-in user can read everyone's invoices |
| `profiles`, `todos`, `categories`, `avatars` | Done right, to catch false alarms |

```bash
npx vibesecure scan examples/leaky-app
npx vibesecure fix examples/leaky-app
```
