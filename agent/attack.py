"""攻撃：やられ役サイトの各脆弱性に本物のHTTPペイロードを送って突破を試みる。

攻撃対象は allowlist で固定された自作サイトのみ（main.py で検査済み）。各脆弱性の
攻撃実装と成功判定は plugins.py の Plugin.attack に集約しており、ここはプラグインを
引いて呼ぶだけの薄いディスパッチャ。修正適用後に同じ関数をもう一度呼ぶと、今度は
弾かれる（success=False）ことで防御を証明する。
"""
from __future__ import annotations

import httpx

from plugins import PLUGINS, AttackResult, VulnId

__all__ = ["AttackResult", "attack"]


async def attack(client: httpx.AsyncClient, target: str, vuln: VulnId) -> AttackResult:
    plugin = PLUGINS.get(vuln)
    if plugin is None:
        return AttackResult(False, "未知の脆弱性", "")
    return await plugin.attack(client, target)
