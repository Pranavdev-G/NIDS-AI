import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(request: Request) {
  const data = await request.json();
  const ip = data.ip || "";
  const reason = data.reason || "Manual block";

  if (ip) {
    // Add to BlockedIP (upsert to ignore duplicates)
    await db.blockedIP.upsert({
      where: { ip },
      update: { reason },
      create: { ip, reason }
    });

    // Increment blocked counter in SystemStat
    await db.systemStat.updateMany({
      where: { id: "global" },
      data: { connectionsBlocked: { increment: 1 } }
    });

    // Update active network events matching source IP to blocked status
    await db.networkEvent.updateMany({
      where: { source_ip: ip },
      data: { status: "blocked" }
    });

    // Update active alerts matching source IP to blocked status
    await db.alert.updateMany({
      where: { source_ip: ip, status: "detected" },
      data: { status: "blocked" }
    });
  }

  return NextResponse.json({
    id: Math.random().toString(36).substring(2, 10),
    timestamp: new Date().toISOString(),
    action: "block",
    ip,
    reason,
    status: "blocked"
  });
}
