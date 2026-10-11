import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";

export default function MyPosts() {
  const { user } = useAuth();
  const [posts, setPosts] = useState<{ id: string; title: string }[]>([]);

  useEffect(() => {
    if (!user) return;
    supabase
      .from("posts")
      .select("id, title")
      .eq("user_id", user.id)
      .then(({ data }) => setPosts(data ?? []));
  }, [user]);

  async function addPost(title: string) {
    await supabase.from("posts").insert({ title, user_id: user!.id });
  }

  return (
    <main>
      <h1>My drafts</h1>
      <ul>{posts.map((p) => <li key={p.id}>{p.title}</li>)}</ul>
      <button onClick={() => addPost("Untitled")}>New draft</button>
    </main>
  );
}
