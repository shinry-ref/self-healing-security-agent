import { NextResponse } from "next/server";
import { debugExposure } from "@/lib/vulns/misconfig";

export const dynamic = "force-dynamic";

// デバッグ用エンドポイント。設定ミスの攻撃面。
// 脆弱版では認証なしで内部情報が丸見え、安全版では 403。
export async function GET() {
  const result = debugExposure();
  if (!result.exposed) {
    return NextResponse.json({ error: "Not found" }, { status: 403 });
  }
  return NextResponse.json(result.data);
}
