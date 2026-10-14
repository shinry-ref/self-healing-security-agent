"""修復：突破された原因を特定し、安全な修正コード（差分）を生成する。

判断の核は Gemini に任せる（GEMINI_API_KEY があるとき）。鍵が無い・失敗した場合も
デモが止まらないよう、plugins.py の各 Plugin.fix（やられ役サイトの実コードに対応した
確実なフォールバック差分）を返す。いずれも「どのファイルの・どこを・なぜ・どう直すか」を
構造化して返し、フロントの承認バーと差分表示にそのまま渡せる形にする。
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict, dataclass

from plugins import PLUGINS, VulnId


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


def _fallback(vuln: VulnId) -> FixPlan:
    p = PLUGINS[vuln]
    return FixPlan(
        vuln=vuln,
        name=p.name,
        file=p.fix.file,
        location=p.fix.location,
        summary=p.fix.summary,
        diff=p.fix.diff,
        source="フォールバック",
    )


def _use_vertex() -> bool:
    """Vertex AI モード（Cloud Run ではサービスアカウント認証＝鍵レス）を使うか。"""
    v = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").strip().lower()
    return v in ("1", "true", "yes")


async def generate_fix(vuln: VulnId, evidence: str) -> FixPlan:
    """突破された脆弱性の修正案を生成する。Gemini が使えればそれで、だめなら実コード対応の確実な差分で。"""
    api_key = os.environ.get("GEMINI_API_KEY")
    # Vertex AI は鍵不要（ADC）。AI Studio は GEMINI_API_KEY が要る。どちらも無ければフォールバック。
    if not _use_vertex() and not api_key:
        return _fallback(vuln)
    try:
        plan = await asyncio.wait_for(
            asyncio.to_thread(_gemini_fix, vuln, evidence, api_key), timeout=25
        )
        return plan or _fallback(vuln)
    except Exception:
        # 鍵切れ・レート制限・ネットワーク断などでもデモは止めない
        return _fallback(vuln)


def _gemini_fix(vuln: VulnId, evidence: str, api_key: str | None) -> FixPlan | None:
    """Gemini に原因と安全な修正を JSON で答えさせる。失敗時は None（フォールバックへ）。"""
    from google import genai  # 遅延 import（鍵が無い環境を壊さない）

    p = PLUGINS[vuln]
    base = p.fix
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    prompt = f"""あなたはセキュアコーディングの専門家です。やられ役サイト（Next.js/TypeScript）で
次の脆弱性が実証されました。原因を特定し、安全な修正を提案してください。

脆弱性: {p.name}（{vuln}） / {p.cwe} / {p.owasp}
場所: {p.location}
攻撃のされ方: {p.attack_desc}
実証の証拠: {evidence}
対象ファイル: {base.file}

参考となる脆弱なコードと安全な書き方の方向性:
{base.diff}

次の JSON だけを返す（前後に文章を付けない）:
{{"summary": "何をなぜ直すかを日本語1〜2文で", "location": "file:line 形式の箇所", "diff": "unified diff 風のテキスト"}}"""

    if _use_vertex():
        # Cloud Run のサービスアカウント（ADC）で認証。鍵は不要。
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "asia-northeast1")
        client = genai.Client(vertexai=True, project=project, location=location)
    else:
        client = genai.Client(api_key=api_key)

    resp = client.models.generate_content(model=model, contents=prompt)
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
        name=p.name,
        file=base.file,
        location=str(data.get("location") or base.location),
        summary=str(data.get("summary") or base.summary),
        diff=str(data.get("diff") or base.diff),
        source="Gemini",
    )
