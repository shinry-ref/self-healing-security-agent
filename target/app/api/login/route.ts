import { NextResponse } from "next/server";
import { authenticate } from "@/lib/vulns/sqli";
import { issueToken } from "@/lib/vulns/auth";

export const dynamic = "force-dynamic";

// ログイン。SQLインジェクション（入力のSQL連結）の攻撃面。
export async function POST(req: Request) {
  let username = "";
  let password = "";
  try {
    const body = await req.json();
    username = String(body.username ?? "");
    password = String(body.password ?? "");
  } catch {
    return NextResponse.json({ error: "invalid body" }, { status: 400 });
  }

  const { user } = authenticate(username, password);
  if (!user) {
    return NextResponse.json({ error: "認証に失敗しました" }, { status: 401 });
  }

  const token = issueToken(user.id);
  return NextResponse.json({
    token,
    user: { id: user.id, username: user.username, role: user.role },
  });
}
