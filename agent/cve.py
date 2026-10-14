"""照合：偵察で特定した技術を脆弱性DB／自前データと突き合わせ、攻撃候補を作る。

自前データ（OWASP Top 10 / CWE に対応づけた既知パターン）は plugins.py の各 Plugin が
持つ cwe / owasp / note から導く。ENABLE_NVD=1 のとき本物の NVD API も参照して注記を
補強する（デモは自前データ中心なので任意）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from plugins import ATTACK_ORDER, PLUGINS, VulnId


@dataclass
class Candidate:
    vuln: VulnId
    name: str
    cwe: str
    owasp: str
    source: str  # "自前データ" | "CVE/NVD"
    note: str


async def match_candidates(
    client: httpx.AsyncClient, tech: list[str]
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for vid in ATTACK_ORDER:
        p = PLUGINS[vid]
        candidates.append(
            Candidate(
                vuln=vid,
                name=p.name,
                cwe=p.cwe,
                owasp=p.owasp,
                source="自前データ",
                note=p.note,
            )
        )

    if os.environ.get("ENABLE_NVD") == "1" and tech:
        try:
            await _enrich_from_nvd(client, tech[0], candidates)
        except Exception:
            pass  # NVD が落ちていてもデモは自前データで続行
    return candidates


async def _enrich_from_nvd(
    client: httpx.AsyncClient, keyword: str, candidates: list[Candidate]
) -> None:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    res = await client.get(url, params={"keywordSearch": keyword, "resultsPerPage": 1}, timeout=10)
    data = res.json()
    total = data.get("totalResults", 0)
    if total and candidates:
        candidates[0].source = "CVE/NVD"
        candidates[0].note += f"（NVDに{keyword}関連の登録あり: {total}件）"
