import { NextResponse } from "next/server";
import { fetchUrl } from "@/lib/vulns/ssrf";

export const dynamic = "force-dynamic";

// URL 取り込み。SSRF の攻撃面。
// 脆弱版は内部アドレスにも到達し機密を返す。安全版は内部宛先を遮断する。
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get("url") ?? "";
  const result = fetchUrl(url);
  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: result.status });
  }
  return NextResponse.json({ status: result.status, body: result.body });
}
