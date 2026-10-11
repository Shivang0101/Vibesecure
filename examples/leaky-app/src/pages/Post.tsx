import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";

export function CommentBox({ postId }: { postId: string }) {
  const { user } = useAuth();

  async function submit(body: string) {
    await supabase.from("comments").insert({ post_id: postId, author_id: user!.id, body });
  }

  async function uploadInvoice(file: File) {
    await supabase.storage.from("invoices").upload(`${user!.id}/${file.name}`, file);
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(new FormData(e.currentTarget).get("body") as string); }}>
      <textarea name="body" />
      <input type="file" onChange={(e) => e.target.files?.[0] && uploadInvoice(e.target.files[0])} />
      <button type="submit">Comment</button>
    </form>
  );
}
