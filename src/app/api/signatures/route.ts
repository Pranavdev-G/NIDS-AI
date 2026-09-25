import { NextResponse } from "next/server";
import { THREAT_SIGNATURES } from "@/lib/nids-store";

export async function GET() {
  return NextResponse.json({ signatures: THREAT_SIGNATURES });
}
