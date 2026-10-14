import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export const dynamic = "force-dynamic";

// 商品一覧／検索。検索はプレースホルダで安全に実装（攻撃面はログイン側に集約）。
export async function GET(req: Request) {
  const db = getDb();
  const q = new URL(req.url).searchParams.get("q");
  if (q) {
    const rows = db
      .prepare("SELECT id, name, price, description, emoji FROM products WHERE name LIKE ?")
      .all(`%${q}%`);
    return NextResponse.json({ products: rows });
  }
  const rows = db.prepare("SELECT id, name, price, description, emoji FROM products").all();
  return NextResponse.json({ products: rows });
}
