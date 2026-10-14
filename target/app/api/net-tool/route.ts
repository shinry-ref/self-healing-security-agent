import { NextResponse } from "next/server";
import { runNetTool } from "@/lib/vulns/cmdi";

export const dynamic = "force-dynamic";

// ネットワーク診断（ping）ツール。コマンドインジェクションの攻撃面。
// 脆弱版は host にシェルのメタ文字を混ぜると追加コマンドが実行される。安全版は拒否。
export async function GET(req: Request) {
  const host = new URL(req.url).searchParams.get("host") ?? "";
  const result = runNetTool(host);
  if (!result.ok) {
    return NextResponse.json({ error: result.output }, { status: 400 });
  }
  return NextResponse.json({ output: result.output, injected: result.injected });
}
