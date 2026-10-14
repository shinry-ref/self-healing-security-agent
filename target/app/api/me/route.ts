import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { bearerFrom, verifyToken } from "@/lib/vulns/auth";
import type { UserRow } from "@/lib/vulns/sqli";

export const dynamic = "force-dynamic";

// 現在のユーザー情報。「認証の甘さ」の攻撃面（推測トークンでなりすまし）。
export async function GET(req: Request) {
  const token = bearerFrom(req);
  const userId = verifyToken(token);
  if (userId === null) {
    return NextResponse.json({ error: "未認証" }, { status: 401 });
  }
  const db = getDb();
  const user = db
    .prepare("SELECT id, username, role, email FROM users WHERE id = ?")
    .get(userId) as Pick<UserRow, "id" | "username" | "role" | "email"> | undefined;
  if (!user) {
    return NextResponse.json({ error: "ユーザーが存在しません" }, { status: 404 });
  }
  return NextResponse.json({ user });
}
