import { NextResponse } from "next/server";
import { seedDatabaseIfNeeded } from "@/lib/nids-store";
import { db } from "@/lib/db";

export async function GET() {
  await seedDatabaseIfNeeded();

  const stats = await db.systemStat.findUnique({
    where: { id: "global" }
  });

  const uptime = stats ? (Date.now() - new Date(stats.startTime).getTime()) / 1000 : 0;
  const activeConnections = await db.networkEvent.count();

  // Aggregate threat categories count
  const threatEvents = await db.networkEvent.findMany({
    where: { is_threat: true },
    select: { threat_type: true }
  });

  const threatCategories: Record<string, number> = {};
  for (const event of threatEvents) {
    if (event.threat_type) {
      threatCategories[event.threat_type] = (threatCategories[event.threat_type] || 0) + 1;
    }
  }

  // Get last 20 records of traffic history ordered ascending
  const trafficHistory = await db.trafficHistory.findMany({
    orderBy: { timestamp: "asc" },
    take: 20
  });

  return NextResponse.json({
    total_packets: stats?.totalPackets || 0,
    threats_detected: stats?.threatsDetected || 0,
    connections_blocked: stats?.connectionsBlocked || 0,
    ai_analyses: stats?.aiAnalyses || 0,
    uptime_seconds: Math.floor(uptime),
    threat_categories: threatCategories,
    active_connections: activeConnections,
    traffic_history: trafficHistory,
    ollama_status: "simulation_mode" // We'll customize health endpoint to show Ollama status
  });
}
