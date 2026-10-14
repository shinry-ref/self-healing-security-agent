"""実ファイル修正モード（FIX_MODE=file）で使う、脆弱性ごとの「実コード置換」定義。

各エントリは「やられ役サイトの脆弱モジュール内の脆弱コード片（find）」を
「安全なコード片（replace）」へ置き換える指示。承認後、エージェントはこれを
target の /api/control/apply-fix へ送り、target が自分自身のソースを書き換える。
HMR（next dev）が反映し、同じ攻撃が今度は本物の安全コードに弾かれる。

find はファイル内に一意に存在する正確な部分文字列であること。target 側は
元の内容を控えてから書き換えるので、reset で脆弱状態へ正確に復元できる。
"""
from __future__ import annotations

# vuln id -> {"file": 相対パス, "find": 置換前, "replace": 置換後}
PATCHES: dict[str, dict] = {
    "sqli": {
        "file": "lib/vulns/sqli.ts",
        "find": "\n".join([
            r"    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;",
            r"    try {",
            r"      const user = db.prepare(sql).get() as UserRow | undefined;",
        ]),
        "replace": "\n".join([
            r'    const sql = "SELECT * FROM users WHERE username = ? AND password = ?";',
            r"    try {",
            r"      const user = db.prepare(sql).get(username, password) as UserRow | undefined;",
        ]),
    },
    "auth": {
        "file": "lib/vulns/auth.ts",
        "find": "\n".join([
            r"    const m = /^user-(\d+)$/.exec(token);",
            r"    if (m) return Number(m[1]);",
        ]),
        "replace": "\n".join([
            r"    const m = /^user-(\d+)$/.exec(token);",
            r"    if (m) return null;",
        ]),
    },
    "jwt": {
        "file": "lib/vulns/jwt.ts",
        "find": "\n".join([
            r'    if ((header.alg || "").toLowerCase() === "none") {',
            r"      return { ok: true, claims };",
        ]),
        "replace": "\n".join([
            r'    if ((header.alg || "").toLowerCase() === "none") {',
            r'      return { ok: false, reason: "alg=none is not allowed" };',
        ]),
    },
    "access": {
        "file": "lib/vulns/access.ts",
        "find": "\n".join([
            r'  if (isVulnerable("access")) {',
            r"    return true;",
        ]),
        "replace": "\n".join([
            r'  if (isVulnerable("access")) {',
            r"    if (info.requesterUserId === null) return false;",
            r'    if (info.requesterRole === "admin") return true;',
            r"    return info.orderUserId === info.requesterUserId;",
        ]),
    },
    "ssrf": {
        "file": "lib/vulns/ssrf.ts",
        "find": "\n".join([
            r"    if (INTERNAL_RESPONSES[host]) {",
            r"      return { ok: true, status: 200, body: INTERNAL_RESPONSES[host] };",
        ]),
        "replace": "\n".join([
            r"    if (isInternalHost(host)) {",
            r'      return { ok: false, status: 403, reason: "blocked internal host" };',
        ]),
    },
    "pathtraversal": {
        "file": "lib/vulns/pathtraversal.ts",
        "find": r"    const path = resolveUnsafe(name);",
        "replace": r'    const path = PUBLIC_DIR + (name.split(/[\\/]/).pop() || "");',
    },
    "cmdi": {
        "file": "lib/vulns/cmdi.ts",
        "find": r"    const parts = host.split(/\s*(?:;|&&|\|\||\||&)\s*/).filter(Boolean);",
        "replace": "\n".join([
            r'    if (SHELL_META.test(host)) return { ok: false, output: "invalid host", injected: false };',
            r"    const parts = [host];",
        ]),
    },
    "misconfig": {
        "file": "lib/vulns/misconfig.ts",
        "find": r'  if (!isVulnerable("misconfig")) {',
        "replace": r'  if (!isVulnerable("misconfig") || true) {',
    },
    "xss": {
        "file": "lib/vulns/xss.ts",
        "find": "\n".join([
            r'  if (isVulnerable("xss")) {',
            r"    return body;",
        ]),
        "replace": "\n".join([
            r'  if (isVulnerable("xss")) {',
            r"    return escapeHtml(body);",
        ]),
    },
}


import os  # noqa: E402

import manifest  # noqa: E402


def _patch(vuln: str) -> dict | None:
    """書換定義 {file, find, replace}。対象リポジトリの antibody.config.json に
    sourceMap があればそれを優先し、無ければ内蔵デフォルト（PATCHES）を使う。"""
    return manifest.source_patch(vuln) or PATCHES.get(vuln)


def _patched_vulns() -> list[str]:
    """書換対象の脆弱性 id 一覧（内蔵 ＋ マニフェストの sourceMap）。"""
    ids = set(PATCHES.keys())
    ids |= {v for v in PATCHES if manifest.source_patch(v)}
    return list(ids)


def _repo() -> str:
    """target リポジトリのパス（環境変数 TARGET_REPO）。空なら実ファイル編集は無効。"""
    return os.environ.get("TARGET_REPO", "")


def enabled() -> bool:
    """実ファイル修正モードが有効か（FIX_MODE=file かつ TARGET_REPO 設定済み）。"""
    return os.environ.get("FIX_MODE") == "file" and bool(_repo())


def repo_available() -> bool:
    """リポジトリのソース編集が物理的に可能か（TARGET_REPO 設定済み）。FIX_MODE に依存しない。
    ランタイムでモードを file に切り替えてよいかの判定に使う。"""
    return bool(_repo())


def apply_source_fix(vuln: str) -> tuple[bool, str]:
    """脆弱モジュールの実ソースを安全版へ書き換える。(成功, 対象ファイル or 理由)。"""
    repo, p = _repo(), _patch(vuln)
    if not repo or not p:
        return False, "TARGET_REPO 未設定または対象外"
    path = os.path.join(repo, p["file"])
    try:
        content = open(path, encoding="utf-8").read()
        if p["find"] not in content:
            # 既に安全版なら成功扱い、そうでなければ対象コードなし
            return (p["replace"] in content), p["file"]
        open(path, "w", encoding="utf-8").write(content.replace(p["find"], p["replace"], 1))
        return True, p["file"]
    except Exception as e:  # noqa
        return False, str(e)


def restore_source(vuln: str) -> None:
    """安全版へ書き換えたソースを脆弱版へ戻す（デモのやり直し用）。"""
    repo, p = _repo(), _patch(vuln)
    if not repo or not p:
        return
    path = os.path.join(repo, p["file"])
    try:
        content = open(path, encoding="utf-8").read()
        if p["replace"] in content:
            open(path, "w", encoding="utf-8").write(content.replace(p["replace"], p["find"], 1))
    except Exception:  # noqa
        pass


def restore_all() -> None:
    for v in _patched_vulns():
        restore_source(v)
