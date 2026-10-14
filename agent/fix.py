"""修復：突破された原因を特定し、安全な修正コード（差分）を生成する。

判断の核は Gemini に任せる（GEMINI_API_KEY があるとき）。鍵が無い・失敗した場合も
デモが止まらないよう、やられ役サイトの実コード（target/lib/vulns/*.ts）に対応した
確実なフォールバック差分を返す。いずれも「どのファイルの・どこを・なぜ・どう直すか」を
構造化して返し、フロントの承認バーと差分表示にそのまま渡せる形にする。
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass

from vulns import CATALOG, VulnId


@dataclass
class FixPlan:
    vuln: VulnId
    name: str          # 脆弱性名（日本語）
    file: str          # 直すファイル
    location: str      # 箇所（file:line 相当の表示）
    summary: str       # 何をなぜ直すか（1〜2文）
    diff: str          # 承認前に見せる unified diff 風のテキスト
    source: str        # "Gemini" | "フォールバック"

    def to_dict(self) -> dict:
        return asdict(self)


# やられ役サイトの実コードに対応した、確実に正しい修正差分（フォールバックの土台）。
# Gemini 連携が無くてもこの内容でループは完結する。
FIX_DB: dict[VulnId, dict[str, str]] = {
    "sqli": {
        "file": "target/lib/vulns/sqli.ts",
        "location": "lib/vulns/sqli.ts:31 authenticate()",
        "summary": "ユーザー入力を SQL 文字列へ連結していた箇所を、プレースホルダ"
        "（プリペアドステートメント）で分離する。入力が命令として解釈されなくなる。",
        "diff": (
            "--- a/lib/vulns/sqli.ts\n"
            "+++ b/lib/vulns/sqli.ts\n"
            "@@ authenticate()\n"
            "-  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;\n"
            "-  const user = db.prepare(sql).get() as UserRow | undefined;\n"
            "+  const sql = \"SELECT * FROM users WHERE username = ? AND password = ?\";\n"
            "+  const user = db.prepare(sql).get(username, password) as UserRow | undefined;\n"
            "   return { user: user ?? null, sqlUsed: sql };\n"
        ),
    },
    "auth": {
        "file": "target/lib/vulns/auth.ts",
        "location": "lib/vulns/auth.ts:issueToken()/verifyToken()",
        "summary": "推測可能な `user-<id>` 形式のトークンをやめ、乱数＋HMAC 署名の"
        "トークンだけを受理する。改ざん・推測によるなりすましを弾く。",
        "diff": (
            "--- a/lib/vulns/auth.ts\n"
            "+++ b/lib/vulns/auth.ts\n"
            "@@ issueToken()\n"
            "-  const token = `user-${userId}`;        // 推測可能\n"
            "+  const rnd = randomBytes(16).toString(\"hex\");\n"
            "+  const raw = `${userId}.${rnd}`;\n"
            "+  const token = `sess_${raw}.${sign(raw)}`;  // 乱数+HMAC署名\n"
            "@@ verifyToken()\n"
            "-  const m = /^user-(\\d+)$/.exec(token); if (m) return Number(m[1]);\n"
            "+  const m = /^sess_(\\d+\\.[0-9a-f]+)\\.([0-9a-f]{32})$/.exec(token);\n"
            "+  if (!m || sign(m[1]) !== m[2] || !store().has(token)) return null;\n"
            "+  return Number(m[1].split(\".\")[0]);\n"
        ),
    },
    "access": {
        "file": "target/lib/vulns/access.ts",
        "location": "lib/vulns/access.ts:canReadOrder()",
        "summary": "注文を無条件に読めていた箇所へ所有者チェックを追加する。"
        "要求者が注文の所有者、または管理者のときだけ許可する。",
        "diff": (
            "--- a/lib/vulns/access.ts\n"
            "+++ b/lib/vulns/access.ts\n"
            "@@ canReadOrder()\n"
            "-  return true; // 誰でも読めてしまう（危険）\n"
            "+  if (info.requesterUserId === null) return false;\n"
            "+  if (info.requesterRole === \"admin\") return true;\n"
            "+  return info.orderUserId === info.requesterUserId;\n"
        ),
    },
    "misconfig": {
        "file": "target/lib/vulns/misconfig.ts",
        "location": "lib/vulns/misconfig.ts:debugExposure() / api/debug",
        "summary": "認証なしで内部設定と全ユーザー情報を返していたデバッグ用経路を"
        "公開しない（403）。本番に残してはいけない出力を塞ぐ。",
        "diff": (
            "--- a/lib/vulns/misconfig.ts\n"
            "+++ b/lib/vulns/misconfig.ts\n"
            "@@ debugExposure()\n"
            "-  const users = db.prepare(\"SELECT * FROM users\").all() as UserRow[];\n"
            "-  return { exposed: true, data: { note, env, users } };\n"
            "+  return { exposed: false };   // 内部情報は公開しない（/api/debug は 403）\n"
        ),
    },
    "xss": {
        "file": "target/lib/vulns/xss.ts",
        "location": "lib/vulns/xss.ts:renderReviewBody()",
        "summary": "レビュー本文を無加工で出力していた箇所を、表示前に HTML エスケープ"
        "する。投稿された `<script>` がタグではなく文字として表示される。",
        "diff": (
            "--- a/lib/vulns/xss.ts\n"
            "+++ b/lib/vulns/xss.ts\n"
            "@@ renderReviewBody()\n"
            "-  return body; // 無加工でそのまま出力（危険）\n"
            "+  return escapeHtml(body); // 出力時にエスケープ\n"
        ),
    },
}


def _fallback(vuln: VulnId) -> FixPlan:
    meta = CATALOG[vuln]
    info = FIX_DB[vuln]
    return FixPlan(
        vuln=vuln,
        name=meta.name,
        file=info["file"],
        location=info["location"],
        summary=info["summary"],
        diff=info["diff"],
        source="フォールバック",
    )


async def generate_fix(vuln: VulnId, evidence: str) -> FixPlan:
    """突破された脆弱性の修正案を生成する。Gemini が使えればそれで、だめなら実コード対応の確実な差分で。"""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return _fallback(vuln)
    try:
        plan = await asyncio.wait_for(
            asyncio.to_thread(_gemini_fix, vuln, evidence, api_key), timeout=25
        )
        return plan or _fallback(vuln)
    except Exception:
        # 鍵切れ・レート制限・ネットワーク断などでもデモは止めない
        return _fallback(vuln)


def _gemini_fix(vuln: VulnId, evidence: str, api_key: str) -> FixPlan | None:
    """Gemini に原因と安全な修正を JSON で答えさせる。失敗時は None（フォールバックへ）。"""
    from google import genai  # 遅延 import（鍵が無い環境を壊さない）

    meta = CATALOG[vuln]
    base = FIX_DB[vuln]
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    prompt = f"""あなたはセキュアコーディングの専門家です。やられ役サイト（Next.js/TypeScript）で
次の脆弱性が実証されました。原因を特定し、安全な修正を提案してください。

脆弱性: {meta.name}（{vuln}）
場所: {meta.location}
攻撃のされ方: {meta.attack}
実証の証拠: {evidence}
対象ファイル: {base['file']}

参考となる脆弱なコードと安全な書き方の方向性:
{base['diff']}

次の JSON だけを返す（前後に文章を付けない）:
{{"summary": "何をなぜ直すかを日本語1〜2文で", "location": "file:line 形式の箇所", "diff": "unified diff 風のテキスト"}}"""

    resp = genai.Client(api_key=api_key).models.generate_content(
        model=model, contents=prompt
    )
    text = (resp.text or "").strip()
    if text.startswith("```"):
        # ```json ... ``` のコードフェンスを剥がす
        text = text.strip("`")
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    try:
        data = json.loads(text)
    except Exception:
        return None
    return FixPlan(
        vuln=vuln,
        name=meta.name,
        file=base["file"],
        location=str(data.get("location") or base["location"]),
        summary=str(data.get("summary") or base["summary"]),
        diff=str(data.get("diff") or base["diff"]),
        source="Gemini",
    )
