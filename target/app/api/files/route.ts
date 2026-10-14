import { NextResponse } from "next/server";
import { readUserFile } from "@/lib/vulns/pathtraversal";

export const dynamic = "force-dynamic";

// ファイル取得。パストラバーサルの攻撃面。
// 脆弱版は ?name=../ で公開ディレクトリ外を読めてしまう。安全版は 403。
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  const result = readUserFile(name);
  if (!result.ok) {
    return NextResponse.json(
      { error: "ファイルが見つからないか、参照できません", path: result.path },
      { status: 403 }
    );
  }
  return NextResponse.json({ path: result.path, content: result.content });
}
