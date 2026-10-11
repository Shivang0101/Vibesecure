import { createClient } from "@supabase/supabase-js";

// The publishable (anon) key is public by design: it ships in the browser bundle.
// Row-level security is the only thing standing between it and your data.
export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
);
