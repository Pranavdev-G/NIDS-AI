import { NextResponse } from "next/server";
import { chatResponse } from "@/lib/nids-store";

export async function POST(request: Request) {
  const data = await request.json();
  const message = data.message || "";
  const context = data.context || "";

  const simulationMode = process.env.SIMULATION_MODE !== "false";
  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  const modelName = "llama3.2";

  let response = "";
  let modelUsed = "simulation";

  if (!simulationMode) {
    try {
      const systemPrompt = `You are NIDS AI Security Assistant, an expert cyber security assistant built into a Network Intrusion Detection System dashboard.
You help analysts analyze alerts, mitigate threats, and configure firewall blocks.
Current system dashboard stats and context: ${context}
Provide a professional, clear, and concise security-focused response in clean markdown.`;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15-second timeout

      const res = await fetch(`${ollamaBaseUrl}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: modelName,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: message }
          ],
          stream: false
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const json = await res.json();
        response = json.message?.content || json.response;
        modelUsed = `ollama:${modelName}`;
      } else {
        throw new Error(`Ollama returned status ${res.status}`);
      }
    } catch (err: any) {
      console.warn("Ollama chat failed, falling back to simulation:", err.message);
      response = `[Ollama fallback: ${err.message}]\n\n` + chatResponse(message);
      modelUsed = "fallback:simulation";
    }
  } else {
    response = chatResponse(message);
  }

  return NextResponse.json({
    response,
    timestamp: new Date().toISOString(),
    model: modelUsed
  });
}
