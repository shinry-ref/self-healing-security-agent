import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { bearerFrom, verifyToken } from "@/lib/vulns/auth";
import { canReadOrder } from "@/lib/vulns/access";
import type { UserRow } from "@/lib/vulns/sqli";

export const dynamic = "force-dynamic";

interface OrderRow {
  id: number;
  user_id: number;
  total: number;
  items: string;
  address: string;
}

// 注文参照。アクセス制御の不備（IDOR）の攻撃面。
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const db = getDb();
  const order = db
    .prepare("SELECT * FROM orders WHERE id = ?")
    .get(Number(id)) as OrderRow | undefined;
  if (!order) {
    return NextResponse.json({ error: "注文が見つかりません" }, { status: 404 });
  }

  const requesterId = verifyToken(bearerFrom(req));
  let requesterRole: string | null = null;
  if (requesterId !== null) {
    const u = db
      .prepare("SELECT role FROM users WHERE id = ?")
      .get(requesterId) as Pick<UserRow, "role"> | undefined;
    requesterRole = u?.role ?? null;
  }

  if (
    !canReadOrder({
      orderUserId: order.user_id,
      requesterUserId: requesterId,
      requesterRole,
    })
  ) {
    return NextResponse.json({ error: "この注文を参照する権限がありません" }, { status: 403 });
  }

  return NextResponse.json({
    order: {
      id: order.id,
      user_id: order.user_id,
      total: order.total,
      items: JSON.parse(order.items),
      address: order.address,
    },
  });
}
