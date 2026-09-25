import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { THREAT_SIGNATURES } from "@/lib/nids-store";

// Helper to parse CSV raw text into array of objects
function parseCSV(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter(line => line.trim() !== "");
  if (lines.length < 2) return [];

  // Parse header
  const headers = lines[0].split(",").map(h => h.trim().replace(/^["']|["']$/g, "").toLowerCase());
  const results: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    // Simple comma split that respects quotes (for fields with commas, e.g. descriptions)
    const matches = line.match(/(".*?"|[^",\s]+)(?=\s*,|\s*$)/g) || line.split(",");
    const row: Record<string, string> = {};
    
    headers.forEach((header, index) => {
      let val = matches[index] || "";
      val = val.trim().replace(/^["']|["']$/g, "");
      row[header] = val;
    });
    results.push(row);
  }
  return results;
}

export async function POST(request: Request) {
  try {
    const { filename, content, clearExisting } = await request.json();
    if (!content) {
      return NextResponse.json({ error: "No file content provided" }, { status: 400 });
    }

    let parsedData: any[] = [];
    const isJson = filename.toLowerCase().endsWith(".json") || content.trim().startsWith("[");

    if (isJson) {
      try {
        parsedData = JSON.parse(content);
        if (!Array.isArray(parsedData)) {
          parsedData = [parsedData];
        }
      } catch (e: any) {
        return NextResponse.json({ error: "Invalid JSON format: " + e.message }, { status: 400 });
      }
    } else {
      parsedData = parseCSV(content);
      if (parsedData.length === 0) {
        return NextResponse.json({ error: "CSV is empty or invalid" }, { status: 400 });
      }
    }

    // Optional database reset
    if (clearExisting !== false) {
      await db.alert.deleteMany({});
      await db.networkEvent.deleteMany({});
      await db.trafficHistory.deleteMany({});
      await db.systemStat.updateMany({
        where: { id: "global" },
        data: {
          totalPackets: 0,
          threatsDetected: 0,
          connectionsBlocked: 0,
          aiAnalyses: 0,
          startTime: new Date()
        }
      });
    }

    // Fetch list of currently blocked IPs
    const blockedIPs = new Set((await db.blockedIP.findMany({ select: { ip: true } })).map(b => b.ip));

    const eventsToCreate: any[] = [];
    const alertsToCreate: any[] = [];

    const now = Date.now();
    let packetCount = 0;
    let threatCount = 0;
    let blockedCount = 0;

    for (let i = 0; i < parsedData.length; i++) {
      const row = parsedData[i];
      packetCount++;

      // Extract/map common fields with fallbacks
      const source_ip = row.source_ip || row.source || row.src || "192.168.1." + (100 + (i % 50));
      const destination_ip = row.destination_ip || row.destination || row.dst || "10.0.0.1";
      const source_port = parseInt(row.source_port || row.src_port || row.sport || "49152") || 49152;
      const destination_port = parseInt(row.destination_port || row.dst_port || row.dport || "80") || 80;
      const protocol = (row.protocol || row.proto || "TCP").toUpperCase();
      const packet_size = parseInt(row.packet_size || row.size || row.len || "64") || 64;
      let description = row.description || row.info || row.payload || "Normal traffic";

      // Timeline mapping: distribute events back in time (e.g., 5 seconds interval)
      const timestamp = row.timestamp ? new Date(row.timestamp) : new Date(now - (parsedData.length - i) * 5000);

      // Perform rule signature match to detect threat if not explicitly marked
      let is_threat = false;
      let threat_type: string | null = null;
      let severity = "info";
      let pattern_matched: string | null = null;

      if (row.is_threat !== undefined) {
        is_threat = String(row.is_threat).toLowerCase() === "true" || row.is_threat === true || row.is_threat === 1;
        threat_type = row.threat_type || (is_threat ? "Custom Threat" : null);
        severity = row.severity || (is_threat ? "medium" : "info");
        pattern_matched = row.pattern_matched || null;
      } else {
        // Run signature patterns check on description/payload
        const payloadText = (description + " " + (row.payload || "")).toUpperCase();
        for (const [type, sig] of Object.entries(THREAT_SIGNATURES)) {
          const matched = sig.patterns.find(pattern => payloadText.includes(pattern.toUpperCase()));
          if (matched) {
            is_threat = true;
            threat_type = type;
            severity = sig.severity;
            pattern_matched = matched;
            description = sig.description;
            break;
          }
        }
      }

      // Check if IP is blocked
      const isBlocked = blockedIPs.has(source_ip);
      const status = isBlocked ? "blocked" : (is_threat ? "detected" : "allowed");

      if (is_threat) {
        threatCount++;
      }
      if (isBlocked || status === "blocked") {
        blockedCount++;
      }

      const eventId = `evt_${Math.random().toString(36).substring(2, 11)}`;

      eventsToCreate.push({
        id: eventId,
        timestamp,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        packet_size,
        is_threat,
        threat_type,
        severity,
        pattern_matched,
        description,
        status
      });

      // Create high/critical severity alerts
      if (is_threat && (severity === "critical" || severity === "high")) {
        alertsToCreate.push({
          id: eventId, // Match event ID for traceability
          timestamp,
          type: threat_type || "Unknown Threat",
          severity,
          source_ip,
          message: `${threat_type} detected from ${source_ip}`,
          status
        });
      }
    }

    // Write events and alerts in chunks/bulk
    if (eventsToCreate.length > 0) {
      await db.networkEvent.createMany({ data: eventsToCreate });
    }
    if (alertsToCreate.length > 0) {
      await db.alert.createMany({ data: alertsToCreate });
    }

    // Create synthetic Traffic History data for charting based on imported timeline
    const historyMap: Record<string, { packets: number, threats: number }> = {};
    eventsToCreate.forEach(evt => {
      // Group by nearest 15 second intervals
      const timeSecStr = new Date(Math.floor(evt.timestamp.getTime() / 15000) * 15000).toISOString();
      if (!historyMap[timeSecStr]) {
        historyMap[timeSecStr] = { packets: 0, threats: 0 };
      }
      historyMap[timeSecStr].packets++;
      if (evt.is_threat) {
        historyMap[timeSecStr].threats++;
      }
    });

    const historyToCreate = Object.entries(historyMap).map(([ts, counts]) => ({
      timestamp: new Date(ts),
      packets_per_sec: Math.max(1, Math.round(counts.packets / 15)),
      threats: counts.threats
    })).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime()).slice(-60); // Keep last 60 points for charting

    if (historyToCreate.length > 0) {
      await db.trafficHistory.createMany({ data: historyToCreate });
    }

    // Update statistics
    await db.systemStat.updateMany({
      where: { id: "global" },
      data: {
        totalPackets: { increment: packetCount },
        threatsDetected: { increment: threatCount },
        connectionsBlocked: { increment: blockedCount },
        startTime: eventsToCreate.length > 0 ? eventsToCreate[0].timestamp : undefined
      }
    });

    return NextResponse.json({
      success: true,
      message: `Successfully processed ${parsedData.length} records`,
      parsed: parsedData.length,
      threats: threatCount,
      blocked: blockedCount
    });

  } catch (err: any) {
    console.error("Dataset upload failed:", err);
    return NextResponse.json({ error: err.message || "Failed to process dataset" }, { status: 500 });
  }
}
