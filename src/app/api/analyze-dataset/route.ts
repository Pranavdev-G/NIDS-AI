import { NextResponse } from "next/server";
import { db } from "@/lib/db";

// Fallback template builder if Ollama is not active or in simulation mode
function generateDatasetReport(stats: {
  total: number;
  threats: number;
  blocked: number;
  categories: Record<string, number>;
  sources: { source_ip: string; _count: { source_ip: number } }[];
  destinations: { destination_ip: string; destination_port: number; _count: { destination_ip: number } }[];
}) {
  const categoriesStr = Object.entries(stats.categories)
    .map(([cat, count]) => `- **${cat}**: ${count} events`)
    .join("\n");

  const sourcesStr = stats.sources
    .map(s => `- **${s.source_ip}** (${s._count.source_ip} events)`)
    .join("\n");

  const destStr = stats.destinations
    .map(d => `- **${d.destination_ip}:${d.destination_port}** (${d._count.destination_ip} connections)`)
    .join("\n");

  const threatRatio = stats.total > 0 ? ((stats.threats / stats.total) * 100).toFixed(1) : "0.0";

  return `### AI Security Intelligence Report: Dataset Analysis

A comprehensive security scan was performed on the uploaded network log dataset containing **${stats.total.toLocaleString()}** packets.

#### Executive Summary
- **Threat Ratio**: \`${threatRatio}%\` of all traffic contains suspicious patterns.
- **Threats Identified**: **${stats.threats}** malicious events detected.
- **Blocked/Active Mitigations**: **${stats.blocked}** source IPs automatically dropped.

---

#### Threat Categories Distribution
${stats.categories && Object.keys(stats.categories).length > 0 ? categoriesStr : "- No threats identified in this dataset."}

---

#### Top Threat Sources (IP Reputations)
${stats.sources && stats.sources.length > 0 ? sourcesStr : "- No malicious sources identified."}

---

#### Primary Targets & Vulnerable Points
${stats.destinations && stats.destinations.length > 0 ? destStr : "- No high-density target destinations."}

---

#### Recommended Incident Response Plan (IRP)
1. **Firewall Rules Update**: Block the identified malicious IPs at the gateway firewall immediately.
2. **Endpoint Protection Scan**: Execute targeted credential scans on the internal hosts targeting ports that received the threats.
3. **WAF Rule Customization**: Ensure Web Application Firewall (WAF) rule sets for SQL injection and Cross-Site Scripting (XSS) are updated to "blocking" mode.
4. **Traffic Rate Limiting**: Enable packet threshold limits on target servers to protect from further automated enumeration scans.`;
}

export async function POST() {
  try {
    // Aggregate dataset statistics from database
    const total = await db.networkEvent.count();
    const threats = await db.networkEvent.count({ where: { is_threat: true } });
    
    const stats = await db.systemStat.findUnique({ where: { id: "global" } });
    const blocked = stats?.connectionsBlocked || 0;

    // Group threat types
    const threatEvents = await db.networkEvent.groupBy({
      by: ["threat_type"],
      where: { is_threat: true },
      _count: {
        threat_type: true
      }
    });

    const categories: Record<string, number> = {};
    threatEvents.forEach(e => {
      if (e.threat_type) {
        categories[e.threat_type] = e._count.threat_type;
      }
    });

    // Top malicious sources
    const topSources = await db.networkEvent.groupBy({
      by: ["source_ip"],
      where: { is_threat: true },
      _count: {
        source_ip: true
      },
      orderBy: {
        _count: {
          source_ip: "desc"
        }
      },
      take: 5
    });

    // Top targets
    const topTargets = await db.networkEvent.groupBy({
      by: ["destination_ip", "destination_port"],
      where: { is_threat: true },
      _count: {
        destination_ip: true
      },
      orderBy: {
        _count: {
          destination_ip: "desc"
        }
      },
      take: 5
    });

    const reportData = {
      total,
      threats,
      blocked,
      categories,
      sources: topSources,
      destinations: topTargets
    };

    const simulationMode = process.env.SIMULATION_MODE !== "false";
    const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    const modelName = "llama3.2";

    let report = "";
    let modelUsed = "simulation";

    if (!simulationMode) {
      try {
        const prompt = `You are NIDS AI Security Analyst. Generate a professional executive security report based on this aggregated traffic log dataset summary:
- Total Network Packets: ${total}
- Threats Detected: ${threats}
- Connections Blocked: ${blocked}
- Threat Category Breakdown: ${JSON.stringify(categories)}
- Top Suspicious Sources: ${JSON.stringify(topSources.map(s => ({ ip: s.source_ip, count: s._count.source_ip })))}
- Targeted internal hosts: ${JSON.stringify(topTargets.map(d => ({ ip: d.destination_ip, port: d.destination_port, count: d._count.destination_ip })))}

Format the report using clean, readable markdown with clear sections (Executive Summary, Threat Category Breakdown, Top Suspects, Recommended Mitigations). Use bullet points and clean styling. Be concise, expert, and professional.`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000); // 20-second timeout

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
          report = json.response;
          modelUsed = `ollama:${modelName}`;
        } else {
          throw new Error(`Ollama status ${res.status}`);
        }
      } catch (err: any) {
        console.warn("Ollama dataset analysis failed, falling back:", err.message);
        report = `[Ollama fallback: ${err.message}]\n\n` + generateDatasetReport(reportData);
        modelUsed = "fallback:simulation";
      }
    } else {
      report = generateDatasetReport(reportData);
    }

    return NextResponse.json({
      report,
      model: modelUsed,
      timestamp: new Date().toISOString()
    });

  } catch (err: any) {
    console.error("Dataset analysis endpoint failed:", err);
    return NextResponse.json({ error: err.message || "Failed to generate AI dataset analysis" }, { status: 500 });
  }
}
