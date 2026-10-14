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


def _advisory_text(vuln: VulnId) -> str:
    """ソース非開示の相手向けの一般的な修正指針（具体差分を出さない）。"""
    p = PLUGINS[vuln]
    return (
        f"{p.fix_desc}。該当は {p.cwe} / {p.owasp}。"
        f"ソースコードを確認できないため具体的な差分は提示できません。"
        f"該当機能（{p.location}）に上記の対策を実装してください。"
    )


def _advisory_fallback(vuln: VulnId) -> FixPlan:
    """ブラックボックス（外部サイト・ソース無し）向けの修正指針。ファイル名や差分は出さない。"""
    p = PLUGINS[vuln]
    return FixPlan(
        vuln=vuln,
        name=p.name,
        file="（ソース非開示のため特定不可）",
        location=p.location,
        summary=_advisory_text(vuln),
        diff="",  # 差分は出さない（コードが見えないため）
        source="フォールバック",
    )


def _use_vertex() -> bool:
    """Vertex AI モード（Cloud Run ではサービスアカウント認証＝鍵レス）を使うか。"""
    v = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").strip().lower()
    return v in ("1", "true", "yes")


async def generate_fix(vuln: VulnId, evidence: str, black_box: bool = False) -> FixPlan:
    """突破された脆弱性の修正案を生成する。Gemini が使えればそれで、だめなら確実なフォールバックで。

    black_box=True（外部サイト・ソース非開示）のときは、具体的な差分ではなく
    一般的な修正指針だけを返す（コードが見えない相手に file:line 差分を出さない）。
    """
    fb = _advisory_fallback if black_box else _fallback
    api_key = os.environ.get("GEMINI_API_KEY")
    # Vertex AI は鍵不要（ADC）。AI Studio は GEMINI_API_KEY が要る。どちらも無ければフォールバック。
    if not _use_vertex() and not api_key:
        return fb(vuln)
    try:
        plan = await asyncio.wait_for(
            asyncio.to_thread(_gemini_fix, vuln, evidence, api_key, black_box), timeout=25
        )
        return plan or fb(vuln)
    except Exception:
        # 鍵切れ・レート制限・ネットワーク断などでもデモは止めない
        return fb(vuln)


def _gemini_fix(vuln: VulnId, evidence: str, api_key: str | None, black_box: bool = False) -> FixPlan | None:
    """Gemini に原因と安全な修正を JSON で答えさせる。失敗時は None（フォールバックへ）。"""
    from google import genai  # 遅延 import（鍵が無い環境を壊さない）

    p = PLUGINS[vuln]
    base = p.fix
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    if black_box:
        # ソース非開示：具体差分は出さず、CWE/OWASP に沿った一般的な修正指針だけ。
        prompt = f"""あなたはセキュアコーディングの専門家です。許可を得て外部サイトを診断し、
次の脆弱性を実証しました。**ソースコードは入手できません。** 具体的なファイル名や差分は
推測で書かず、一般的で実装言語に依存しない修正指針だけを示してください。

脆弱性: {p.name}（{vuln}） / {p.cwe} / {p.owasp}
場所（機能面）: {p.location}
攻撃のされ方: {p.attack_desc}
実証の証拠: {evidence}

次の JSON だけを返す（前後に文章を付けない）:
{{"summary": "ソースを見ずに実施できる一般的な修正指針を日本語2〜3文で"}}"""
        resp = (
            genai.Client(vertexai=True, project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
                         location=os.environ.get("GOOGLE_CLOUD_LOCATION", "asia-northeast1"))
            if _use_vertex() else genai.Client(api_key=api_key)
        ).models.generate_content(model=model, contents=prompt)
        text = (resp.text or "").strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lstrip().lower().startswith("json"):
                text = text.lstrip()[4:]
        try:
            data = json.loads(text)
        except Exception:
            return None
        return FixPlan(
            vuln=vuln, name=p.name, file="（ソース非開示のため特定不可）",
            location=p.location, summary=str(data.get("summary") or _advisory_text(vuln)),
            diff="", source="Gemini",
        )

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
