"""安全装置：診断してよい相手を許可リストで固定する。

このツールの合法性はこの1ファイルに懸かっている。攻撃できる相手は、環境変数
ALLOWED_TARGETS に明示的に列挙した自作のやられ役サイトだけ。前方一致や部分一致は
せず、完全一致のみを許可する。これにより、ツールを公開しても第三者のサイトを
攻撃する踏み台にはならない。
"""
from __future__ import annotations

import os
from urllib.parse import urlparse


def _normalize(url: str) -> str:
    return url.strip().rstrip("/")


def allowed_targets() -> list[str]:
    raw = os.environ.get("ALLOWED_TARGETS", "")
    return [_normalize(u) for u in raw.split(",") if u.strip()]


def is_allowed(target_url: str) -> bool:
    """target_url が許可リストに完全一致で載っているときだけ True。"""
    if not target_url:
        return False
    # スキームが http/https であることも確認（file:// 等を弾く）
    scheme = urlparse(target_url).scheme
    if scheme not in ("http", "https"):
        return False
    allowed = set(allowed_targets())
    return _normalize(target_url) in allowed


class TargetNotAllowed(Exception):
    """許可リストに無い対象への診断要求。"""
