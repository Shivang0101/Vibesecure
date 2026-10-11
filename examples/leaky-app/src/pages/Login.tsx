import { useSearchParams } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";

export default function Login() {
  const [params] = useSearchParams();
  const next = params.get("next") ?? "/";

  async function signIn(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (!error) window.location.href = next;
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); signIn(String(f.get("email")), String(f.get("password"))); }}>
      <input name="email" type="email" />
      <input name="password" type="password" />
      <button type="submit">Sign in</button>
    </form>
  );
}
