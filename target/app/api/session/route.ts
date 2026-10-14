import { NextResponse } from "next/server";
import { verifySession } from "@/lib/vulns/jwt";
import { bearerFrom } from "@/lib/vulns/auth";

export const dynamic = "force-dynamic";

// API セッション確認。JWT 改ざん（alg=none）の攻撃面。
// 脆弱版は alg=none の署名なしトークンを信頼する。安全版は HS256 署名を必須にする。
export async function GET(req: Request) {
  const result = verifySession(bearerFrom(req));
  if (!result.ok) {
    return NextResponse.json({ error: result.reason ?? "unauthorized" }, { status: 401 });
  }
  return NextResponse.json({ claims: result.claims });
}
