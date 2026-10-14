"""対象リポジトリ固有の設定を外部ファイル（antibody.config.json）から読む。

『検査したいリポジトリに antibody.config.json を置けば、その app に向けて検査できる』
ようにするための externalization レイヤ。固有なのは主に次の2つ：

- endpoints: 各脆弱性の攻撃先パス（app ごとにルート名が違う）。黒箱診断（advisory/
  propose）はこれだけで別 app に向けられる。
- sourceMap: file モードで実ソースを書き換える際の {file, find, replace}。自分の
  リポジトリを直す時だけ必要。

読み込み順：ANTIBODY_CONFIG(明示パス) → TARGET_REPO/antibody.config.json → 無ければ
空（呼び出し側が渡す内蔵デフォルトを使う）。設定は静的なのでプロセス内でキャッシュする。
"""
from __future__ import annotations

import functools
import json
import os


@functools.lru_cache(maxsize=1)
def _config() -> dict:
    path = os.environ.get("ANTIBODY_CONFIG", "")
    if not path:
        repo = os.environ.get("TARGET_REPO", "")
        if repo:
            path = os.path.join(repo, "antibody.config.json")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def name() -> str:
    return str(_config().get("name", ""))


def loaded() -> bool:
    """外部マニフェストを実際に読み込めたか（デフォルトではなく app 固有設定か）。"""
    return bool(_config())


def endpoint(vuln: str, default: str) -> str:
    """脆弱性 vuln の攻撃先パス。マニフェストに無ければ default（内蔵）を返す。"""
    eps = _config().get("endpoints") or {}
    return str(eps.get(vuln, default))


def source_patch(vuln: str) -> dict | None:
    """file モードの書換定義 {file, find, replace}。マニフェストに無ければ None。"""
    sm = _config().get("sourceMap") or {}
    return sm.get(vuln)
