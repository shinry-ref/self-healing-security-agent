import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { renderReviewBody } from "@/lib/vulns/xss";

export const dynamic = "force-dynamic";

interface ReviewRow {
  id: number;
  product_id: number;
  author: string;
  body: string;
  created_at: string;
}

// レビュー一覧。body_html は表示用に変換した文字列。
// 脆弱版では無加工（XSSが成立）、安全版ではエスケープ済み。
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();
  const rows = db
    .prepare("SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC")
    .all(Number(id)) as ReviewRow[];
  const reviews = rows.map((r) => ({
    id: r.id,
    author: r.author,
    created_at: r.created_at,
    body_html: renderReviewBody(r.body),
  }));
  return NextResponse.json({ reviews });
}

// レビュー投稿。本文はそのまま保存し、表示時の処理で脆弱性が決まる（格納型XSS）。
export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  let author = "匿名";
  let body = "";
  try {
    const json = await req.json();
    author = String(json.author ?? "匿名");
    body = String(json.body ?? "");
  } catch {
    return NextResponse.json({ error: "invalid body" }, { status: 400 });
  }
  const db = getDb();
  const info = db
    .prepare(
      "INSERT INTO reviews (product_id, author, body, created_at) VALUES (?,?,?,?)"
    )
    .run(Number(id), author, body, new Date().toISOString());
  return NextResponse.json({ id: info.lastInsertRowid }, { status: 201 });
}
