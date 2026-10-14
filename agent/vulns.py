"""脆弱性カタログ（プラグイン定義 plugins.py から導出）。

やられ役サイト側 lib/vulns と同じ id の語彙を共有し、攻撃・修正・再チェックの
三者が食い違わないようにする。実体は plugins.py の PLUGINS 一箇所にあり、ここは
従来の CATALOG / ATTACK_ORDER 形へ変換して見せるだけの薄い層。
"""
from __future__ import annotations

from dataclasses import dataclass

from plugins import ATTACK_ORDER, PLUGINS, VulnId

__all__ = ["VulnId", "VulnMeta", "CATALOG", "ATTACK_ORDER"]


@dataclass(frozen=True)
class VulnMeta:
    id: VulnId
    name: str          # 日本語名
    location: str      # 仕込まれる場所
    attack: str        # 攻撃のされ方
    fix: str           # 直し方
    severity: str      # high | medium | low
    data_node: str     # 侵入マップで「突破される」到達先ノード
    data_node_label: str


CATALOG: dict[VulnId, VulnMeta] = {
    vid: VulnMeta(
        id=p.id,
        name=p.name,
        location=p.location,
        attack=p.attack_desc,
        fix=p.fix_desc,
        severity=p.severity,
        data_node=p.data_node,
        data_node_label=p.data_node_label,
    )
    for vid, p in PLUGINS.items()
}
