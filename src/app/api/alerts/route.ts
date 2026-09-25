import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  const dbAlerts = await db.alert.findMany({
    orderBy: { timestamp: "desc" },
    take: 100
  });

  return NextResponse.json({
    alerts: dbAlerts.reverse(),
    total: dbAlerts.length
  });
}
