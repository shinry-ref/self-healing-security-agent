import { NextResponse } from "next/server";
import { snapshot } from "@/lib/vulns/registry";
import { checkControlToken } from "@/lib/control";

export const dynamic = "force-dynamic";

// 現在の脆弱性構成を返す（エージェント専用。再チェックの答え合わせ等に使う）。
export async function GET(req: Request) {
  if (!checkControlToken(req)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  return NextResponse.json(snapshot());
}
