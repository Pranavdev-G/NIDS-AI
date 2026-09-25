import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  const history = await db.trafficHistory.findMany({
    orderBy: { timestamp: "asc" },
    take: 60
  });

  return NextResponse.json({ history });
}

