import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  const threatEvents = await db.networkEvent.findMany({
    where: { is_threat: true },
    select: { threat_type: true }
  });

  const categories: Record<string, number> = {};
  for (const event of threatEvents) {
    if (event.threat_type) {
      categories[event.threat_type] = (categories[event.threat_type] || 0) + 1;
    }
  }

  return NextResponse.json({ categories });
}
