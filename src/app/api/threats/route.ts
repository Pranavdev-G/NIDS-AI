import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const limit = parseInt(searchParams.get("limit") || "50");
  const severity = searchParams.get("severity");
  const type = searchParams.get("type");

  const where: any = { is_threat: true };
  if (severity) where.severity = severity;
  if (type) where.threat_type = type;

  const dbThreats = await db.networkEvent.findMany({
    where,
    orderBy: { timestamp: "desc" },
    take: limit
  });

  return NextResponse.json({
    threats: dbThreats.reverse(),
    total: await db.networkEvent.count({ where: { is_threat: true } })
  });
}
