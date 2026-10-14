"""脆弱性カタログ（やられ役サイト側 lib/vulns と同じ語彙）。

エージェントとやられ役サイトが同じ id を共有することで、攻撃・修正・再チェックの
三者が食い違わないようにする。
"""
from __future__ import annotations

from dataclasses import dataclass

VulnId = str  # "sqli" | "xss" | "auth" | "access" | "misconfig"


@dataclass(frozen=True)
class VulnMeta:
    id: VulnId
    name: str          # 日本語名
    location: str      # 仕込まれる場所
    attack: str        # 攻撃のされ方
    fix: str           # 直し方
    severity: str      # high | medium | low
    # 侵入マップで「突破される」到達先ノード
    data_node: str
    data_node_label: str


CATALOG: dict[VulnId, VulnMeta] = {
    "sqli": VulnMeta(
        id="sqli",
        name="SQLインジェクション",
        location="ログイン",
        attack="入力をSQL文にそのまま連結",
        fix="プレースホルダで入力を分離",
        severity="high",
        data_node="db_auth",
        data_node_label="認証DB",
    ),
    "auth": VulnMeta(
        id="auth",
        name="認証の甘さ",
        location="セッション",
        attack="推測可能なトークンでなりすまし",
        fix="強いトークン・検証を追加",
        severity="high",
        data_node="session",
        data_node_label="管理者セッション",
    ),
    "access": VulnMeta(
        id="access",
        name="アクセス制御の不備",
        location="注文履歴",
        attack="IDを変えると他人の情報が見える",
        fix="所有者チェックを追加",
        severity="high",
        data_node="orders",
        data_node_label="顧客注文データ",
    ),
    "misconfig": VulnMeta(
        id="misconfig",
        name="設定ミス",
        location="管理・デバッグ",
        attack="公開すべきでない内部情報が露出",
        fix="公開範囲を制限",
        severity="medium",
        data_node="internal",
        data_node_label="内部設定・全ユーザー",
    ),
    "xss": VulnMeta(
        id="xss",
        name="XSS（格納型）",
        location="レビュー投稿",
        attack="入力を無加工で画面に出力",
        fix="出力時にエスケープ",
        severity="high",
        data_node="review_view",
        data_node_label="レビュー表示",
    ),
}

# 攻撃を試す順序（連鎖的侵入の物語になる順）
ATTACK_ORDER: list[VulnId] = ["sqli", "auth", "misconfig", "access", "xss"]
