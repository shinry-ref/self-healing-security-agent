"""偵察：対象にアクセスし、技術スタック・ページ・入力欄を洗い出す。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx


@dataclass
class ReconReport:
    tech: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)


HREF_RE = re.compile(r'href="(/[^"#?]*)"')


async def run_recon(client: httpx.AsyncClient, target: str) -> ReconReport:
    report = ReconReport()
    try:
        res = await client.get(target + "/", timeout=10)
        html = res.text
    except Exception:
        return report

    # 技術スタックの推定
    if "/_next/" in html or res.headers.get("x-powered-by", "").lower().startswith("next"):
        report.tech.append("Next.js")
        report.tech.append("React")
    server = res.headers.get("server")
    if server:
        report.tech.append(server)

    # リンクからページを収集（相対パス）
    found = {m.group(1).rstrip("/") or "/" for m in HREF_RE.finditer(html)}
    report.pages = sorted(p for p in found if not p.startswith("/_next"))

    # 想定される攻撃面（やられ役サイトの既知エンドポイント）
    report.endpoints = [
        "POST /api/login",
        "GET /api/me",
        "GET /api/orders/{id}",
        "GET /api/debug",
        "POST /api/products/{id}/reviews",
    ]

    # ログインフォームの入力欄（偵察でよく狙う箇所）
    if "/login" in "".join(report.pages):
        report.inputs = ["username", "password"]

    return report
