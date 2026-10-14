import { NextResponse } from "next/server";
import { reset, snapshot } from "@/lib/vulns/registry";
import { reseedDb } from "@/lib/db";
import { checkControlToken } from "@/lib/control";

export const dynamic = "force-dynamic";

// 脆弱性構成を作り直し、DBを初期化する（デモのやり直し）。
// seed 省略 or 0 → 全5種有効、それ以外 → seed から決定的な部分集合（ランダム組込）。
export async function POST(req: Request) {
  if (!checkControlToken(req)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  let seed: number | undefined;
  try {
    const body = await req.json();
    if (body && typeof body.seed === "number") seed = body.seed;
  } catch {
    // body なしは全5種
  }
  reset(seed);
  reseedDb();
  return NextResponse.json(snapshot());
}
