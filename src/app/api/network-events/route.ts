import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const limit = parseInt(searchParams.get("limit") || "100");

  const dbEvents = await db.networkEvent.findMany({
    orderBy: { timestamp: "desc" },
    take: limit
  });

  return NextResponse.json({
    events: dbEvents.reverse(),
    total: await db.networkEvent.count()
  });
}
