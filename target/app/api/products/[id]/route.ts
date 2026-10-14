import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();
  const product = db
    .prepare("SELECT id, name, price, description, emoji FROM products WHERE id = ?")
    .get(Number(id));
  if (!product) {
    return NextResponse.json({ error: "商品が見つかりません" }, { status: 404 });
  }
  return NextResponse.json({ product });
}
