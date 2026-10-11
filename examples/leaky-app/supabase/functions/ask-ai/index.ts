// Answers questions with an AI model. Nothing checks who is calling or how
// often, and verify_jwt is off: anyone can run up the AI bill.
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  const { question } = await req.json();
  const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${Deno.env.get("LOVABLE_API_KEY")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "google/gemini-2.5-flash",
      messages: [{ role: "user", content: question }],
    }),
  });

  if (response.status === 429) {
    return new Response(JSON.stringify({ error: "Rate limit exceeded, try again later." }), {
      status: 429,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
  const data = await response.json();
  return new Response(JSON.stringify({ answer: data.choices[0].message.content }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
