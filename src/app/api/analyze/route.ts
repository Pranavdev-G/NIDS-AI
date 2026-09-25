import { NextResponse } from "next/server";
import { generateAnalysis } from "@/lib/nids-store";
import { db } from "@/lib/db";

export async function POST(request: Request) {
  const data = await request.json();
  const threat = data.threat || {};

  // Increment AI Analyses count in database
  await db.systemStat.updateMany({
    where: { id: "global" },
    data: { aiAnalyses: { increment: 1 } }
  });

  const simulationMode = process.env.SIMULATION_MODE !== "false";
  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  const modelName = "llama3.2";

  let analysis = "";
  let modelUsed = "simulation";

  if (!simulationMode) {
    try {
      const prompt = `Analyze this security threat event detected by our Network Intrusion Detection System (NIDS):
Threat Type: ${threat.threat_type || "Unknown"}
Severity: ${threat.severity || "Unknown"}
Source IP: ${threat.source_ip || "Unknown"}
Destination IP: ${threat.destination_ip || "Unknown"}
Destination Port: ${threat.destination_port || "Unknown"}
Protocol: ${threat.protocol || "Unknown"}
Matched Pattern: ${threat.pattern_matched || "None"}
Description: ${threat.description || "None"}

Provide a detailed threat analysis, including:
1. Threat Vector: How this attack works.
2. Potential Impact: What harm can be caused.
3. Recommended Actions: Bullet points of mitigation steps (e.g., whether to block source IP, patch systems, etc.).

Keep the response professional, concise, and structured in clean markdown format.`;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15-second timeout for LLM generation

      const res = await fetch(`${ollamaBaseUrl}/api/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: modelName,
          prompt,
          stream: false
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const json = await res.json();
        analysis = json.response;
        modelUsed = `ollama:${modelName}`;
      } else {
        throw new Error(`Ollama returned status ${res.status}`);
      }
    } catch (err: any) {
      console.warn("Ollama query failed, falling back to simulation:", err.message);
      analysis = `[Ollama fallback: ${err.message}]\n\n` + generateAnalysis(threat);
      modelUsed = "fallback:simulation";
    }
  } else {
    analysis = generateAnalysis(threat);
  }

  return NextResponse.json({
    id: Math.random().toString(36).substring(2, 10),
    timestamp: new Date().toISOString(),
    threat_data: threat,
    analysis,
    model: modelUsed
  });
}
