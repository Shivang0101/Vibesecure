// Upgrades a user after they pay. It never checks Stripe's signature, so
// anyone who finds the URL can send a fake "checkout.session.completed".
import { createClient } from "npm:@supabase/supabase-js@2";

const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  const event = await req.json();

  if (event.type === "checkout.session.completed") {
    const userId = event.data.object.client_reference_id;
    await admin.from("profiles").update({ role: "admin" }).eq("id", userId);
  }
  return new Response(JSON.stringify({ received: true }), { status: 200 });
});
