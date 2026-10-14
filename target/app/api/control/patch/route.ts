import { NextResponse } from "next/server";
import { applyPatch, unpatch, snapshot } from "@/lib/vulns/registry";
import { ALL_VULNS, type VulnId } from "@/lib/vulns/types";
import { checkControlToken } from "@/lib/control";

export const dynamic = "force-dynamic";

// 修正の適用／取り消し（エージェント専用）。
// 承認後にエージェントがここを呼ぶ＝「生成した修正コードを本番に反映」に相当。
// body: { vuln: VulnId, action?: "patch" | "unpatch" }
export async function POST(req: Request) {
  if (!checkControlToken(req)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  let vuln: string | undefined;
  let action = "patch";
  try {
    const body = await req.json();
    vuln = body.vuln;
    if (body.action) action = String(body.action);
  } catch {
    return NextResponse.json({ error: "invalid body" }, { status: 400 });
  }
  if (!vuln || !ALL_VULNS.includes(vuln as VulnId)) {
    return NextResponse.json({ error: "unknown vuln" }, { status: 400 });
  }
  if (action === "unpatch") {
    unpatch(vuln as VulnId);
  } else {
    applyPatch(vuln as VulnId);
  }
  return NextResponse.json(snapshot());
}
