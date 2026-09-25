import { NextResponse } from "next/server";

export async function GET() {
  const simulationMode = process.env.SIMULATION_MODE !== "false";
  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";

  let ollamaConnected = false;
  let ollamaMessage = "simulation_mode";

  if (!simulationMode) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000); // 2-second timeout
      const res = await fetch(`${ollamaBaseUrl}/api/tags`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        ollamaConnected = true;
        ollamaMessage = "connected";
      } else {
        ollamaMessage = `server returned ${res.status}`;
      }
    } catch (err: any) {
      ollamaMessage = `could not connect: ${err.message}`;
    }
  }

  return NextResponse.json({
    status: "healthy",
    ollama: { connected: ollamaConnected, message: ollamaMessage, model: "llama3.2" },
    simulation_mode: simulationMode,
    timestamp: new Date().toISOString()
  });
}
