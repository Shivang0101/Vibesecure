import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";

export default function Notes() {
  const { user } = useAuth();
  const [notes, setNotes] = useState<{ id: number; content: string }[]>([]);

  useEffect(() => {
    if (!user) return;
    supabase
      .from("notes")
      .select("id, content")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .then(({ data }) => setNotes(data ?? []));
  }, [user]);

  async function deleteNote(id: number) {
    await supabase.from("notes").delete().eq("id", id);
  }

  return (
    <ul>
      {notes.map((n) => (
        <li key={n.id}>
          {n.content} <button onClick={() => deleteNote(n.id)}>Delete</button>
        </li>
      ))}
    </ul>
  );
}
