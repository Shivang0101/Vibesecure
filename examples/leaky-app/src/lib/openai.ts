// Calls OpenAI straight from the browser. VITE_ variables are built into the
// website, so the key is public.
const apiKey = import.meta.env.VITE_OPENAI_API_KEY;

export async function summarize(text: string): Promise<string> {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: `Summarize: ${text}` }] }),
  });
  const data = await response.json();
  return data.choices[0].message.content;
}
