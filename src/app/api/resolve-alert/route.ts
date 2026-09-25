import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(request: Request) {
  const data = await request.json();
  const alertId = data.id || "";

  await db.alert.updateMany({
    where: { id: alertId },
    data: { status: "resolved" }
  });

  // Also resolve matching network event status
  await db.networkEvent.updateMany({
    where: { id: alertId },
    data: { status: "resolved" }
  });

  return NextResponse.json({ status: "resolved", alert_id: alertId });
}
