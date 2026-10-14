"""偵察：対象を自律的にクロールし、攻撃面（入力欄・パラメータ・エンドポイント）を発見する。

ハードコードした既知エンドポイントに頼らず、実際にページを巡回してフォーム・リンク・
API を洗い出す。見つけた攻撃面は scanner.py の汎用検査エンジンがそのまま使う。
これにより「対象ごとに攻撃を手書きする」必要がなくなる。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

import httpx


@dataclass
class Form:
    action: str            # 絶対URL
    method: str            # GET | POST
    fields: list[str]      # input/textarea の name
    has_password: bool = False


@dataclass
class Endpoint:
    url: str               # 絶対URL（クエリなし）
    methods: list[str] = field(default_factory=lambda: ["GET"])
    params: list[str] = field(default_factory=list)   # 既知/発見済みのクエリ/ボディ名
    note: str = ""


@dataclass
class ReconReport:
    tech: list[str] = field(default_factory=list)
    version: str | None = None
    pages: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)

    def all_inputs(self) -> int:
        n = sum(len(f.fields) for f in self.forms)
        n += sum(len(e.params) for e in self.endpoints)
        return n


HREF_RE = re.compile(r'href="([^"#]+)"')
FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ACTION_RE = re.compile(r'action="([^"]*)"', re.IGNORECASE)
METHOD_RE = re.compile(r'method="([^"]*)"', re.IGNORECASE)
INPUT_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*\bname="([^"]+)"[^>]*>', re.IGNORECASE)
TYPE_RE = re.compile(r'type="([^"]*)"', re.IGNORECASE)
NEXT_DATA_RE = re.compile(r'/_next/static/[^"]*?/([0-9]+\.[0-9]+\.[0-9]+)/')

# 攻撃面としてよく存在する API/機密パスの候補辞書（汎用スキャナの常套）。
# 実在チェックして、応答があったものだけを攻撃面に加える。
CANDIDATE_ENDPOINTS: list[tuple[str, list[str], list[str]]] = [
    # (パス, メソッド群, 想定パラメータ名)
    ("/api/login", ["POST"], ["username", "password"]),
    ("/api/me", ["GET"], []),
    ("/api/session", ["GET"], []),
    ("/api/debug", ["GET"], []),
    ("/api/config", ["GET"], []),
    ("/.env", ["GET"], []),
    ("/api/orders/1001", ["GET"], []),
    ("/api/orders/1002", ["GET"], []),
    ("/api/products/1/reviews", ["GET", "POST"], ["author", "body"]),
    ("/api/files", ["GET"], ["name", "file", "path"]),
    ("/api/net-tool", ["GET"], ["host", "cmd", "target"]),
    ("/api/fetch", ["GET"], ["url", "uri", "next"]),
]


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _parse_forms(base_url: str, html: str) -> list[Form]:
    forms: list[Form] = []
    for m in FORM_RE.finditer(html):
        block = m.group(0)
        inner = m.group(1)
        action_m = ACTION_RE.search(block)
        method_m = METHOD_RE.search(block)
        action = urljoin(base_url, action_m.group(1)) if action_m and action_m.group(1) else base_url
        method = (method_m.group(1).upper() if method_m else "GET")
        fields = INPUT_RE.findall(inner)
        has_pw = bool(re.search(r'type="password"', inner, re.IGNORECASE))
        if fields:
            forms.append(Form(action=action, method=method, fields=fields, has_password=has_pw))
    return forms


async def run_recon(client: httpx.AsyncClient, target: str, max_pages: int = 12) -> ReconReport:
    report = ReconReport()
    origin = target.rstrip("/")

    # 1) トップページ取得＋技術スタック推定
    try:
        res = await client.get(origin + "/", timeout=10)
        html = res.text
    except Exception:
        return report

    if "/_next/" in html or res.headers.get("x-powered-by", "").lower().startswith("next"):
        report.tech += ["Next.js", "React"]
    server = res.headers.get("server")
    if server:
        report.tech.append(server)
    vm = NEXT_DATA_RE.search(html)
    if vm:
        report.version = vm.group(1)

    # 2) 幅優先クロール（同一オリジン・最大 max_pages ページ）
    seen: set[str] = set()
    queue: list[str] = ["/"]
    forms_by_action: dict[str, Form] = {}
    while queue and len(seen) < max_pages:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        url = origin + path
        try:
            page = (await client.get(url, timeout=10)).text if path != "/" else html
        except Exception:
            continue
        for f in _parse_forms(url, page):
            forms_by_action.setdefault(f.action + "|" + f.method, f)
        for m in HREF_RE.finditer(page):
            href = m.group(1)
            absu = urljoin(url, href)
            if not _same_origin(origin + "/", absu):
                continue
            pu = urlparse(absu)
            p = pu.path.rstrip("/") or "/"
            if p.startswith("/_next"):
                continue
            if p not in seen and p not in queue:
                queue.append(p)

    report.pages = sorted(seen)
    report.forms = list(forms_by_action.values())

    # 3) 候補エンドポイント辞書を実在チェックして攻撃面へ
    for path, methods, params in CANDIDATE_ENDPOINTS:
        url = origin + path
        exists = False
        for mth in methods:
            try:
                if mth == "GET":
                    r = await client.get(url, timeout=8)
                else:
                    r = await client.request(mth, url, json={}, timeout=8)
                # 404/405 以外は「存在する攻撃面」とみなす（401/403/400/200 等）
                if r.status_code not in (404, 405):
                    exists = True
            except Exception:
                continue
        if exists:
            report.endpoints.append(Endpoint(url=url, methods=methods, params=params))

    return report
