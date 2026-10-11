import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function Search() {
  const [results, setResults] = useState<{ id: string; title: string }[]>([]);

  async function search(query: string) {
    const { data } = await supabase
      .from("posts")
      .select("id, title")
      .or(`title.ilike.%${query}%,body.ilike.%${query}%`);
    setResults(data ?? []);
  }

  async function deepSearch(query: string) {
    const { data } = await supabase.rpc("search_posts", { term: query });
    setResults(data ?? []);
  }

  return (
    <div>
      <input onChange={(e) => search(e.target.value)} />
      <button onClick={() => deepSearch("draft")}>Search everything</button>
      <ul>{results.map((r) => <li key={r.id}>{r.title}</li>)}</ul>
    </div>
  );
}
