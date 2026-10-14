"""照合：偵察で特定した技術を脆弱性DB／自前データと突き合わせ、攻撃候補を作る。

本番では CVE/NVD を引く余地を残しつつ、デモの確実性のため自前データ（OWASP Top 10 /
CWE に対応づけた既知パターン）を主に使う。ENABLE_NVD=1 のとき NVD API も参照する。
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from vulns import ATTACK_ORDER, CATALOG, VulnId


@dataclass
class Candidate:
    vuln: VulnId
    name: str
    cwe: str
    owasp: str
    source: str  # "自前データ" | "CVE/NVD"
    note: str


# 自前データ：5パターンを CWE / OWASP に対応づけたもの
SELF_DB: dict[VulnId, dict[str, str]] = {
    "sqli": {"cwe": "CWE-89", "owasp": "A03:2021 インジェクション",
             "note": "ユーザー入力をSQLに連結する実装は古典的な攻撃対象"},
    "xss": {"cwe": "CWE-79", "owasp": "A03:2021 インジェクション",
            "note": "出力エスケープ漏れによる格納型XSS"},
    "auth": {"cwe": "CWE-330", "owasp": "A07:2021 識別と認証の失敗",
             "note": "推測可能なセッショントークン"},
    "access": {"cwe": "CWE-639", "owasp": "A01:2021 アクセス制御の不備",
               "note": "所有者チェック欠如による IDOR"},
    "misconfig": {"cwe": "CWE-200", "owasp": "A05:2021 セキュリティ設定ミス",
                  "note": "デバッグ情報の意図しない公開"},
}


async def match_candidates(
    client: httpx.AsyncClient, tech: list[str]
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for vid in ATTACK_ORDER:
        meta = CATALOG[vid]
        info = SELF_DB[vid]
        candidates.append(
            Candidate(
                vuln=vid,
                name=meta.name,
                cwe=info["cwe"],
                owasp=info["owasp"],
                source="自前データ",
                note=info["note"],
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
