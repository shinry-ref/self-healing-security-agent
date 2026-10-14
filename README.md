# アンチボディ（Antibody）— 自己修復型・侵入実証エージェント

> 第5回 Agentic AI Hackathon 提出作品

## ライブデモ（Google Cloud Run）

- **ダッシュボード**: https://antibody-frontend-545546547932.asia-northeast1.run.app
- エージェント API: https://antibody-agent-545546547932.asia-northeast1.run.app
- やられ役サイト（NEKO MART・診断デモ用）: https://antibody-target-545546547932.asia-northeast1.run.app

ダッシュボードで「診断開始」を押すと、9種の脆弱性に対する 攻撃→修復→承認→再証明の自己修復ループが可視化されます。

AIエージェントが **自作のやられ役サイト** に自律的に侵入して脆弱性を実証し、原因を特定して修正コードを生成、**人間の承認を得てから** 適用し、同じ攻撃を再実行して「今度は弾かれる」ことまで証明する — この **攻撃→修復→再証明の自己修復ループ** をリアルタイムに可視化するセキュリティ診断ツールです。

## 合法性の鉄則（最重要）

**攻撃できる相手は、許可リストに載った自作のやられ役サイトだけ。** 任意の外部URLは実行せず 403 で弾きます（`agent/allowlist.py`、完全一致のみ）。これによりツールを公開しても第三者の踏み台にされません。対象サイトは「わざと脆弱にした診断デモ用」であることを画面に明示します。

## 構成（モノレポ）

| ディレクトリ | 技術 | 役割 |
|---|---|---|
| `target/` | Next.js (TS) | やられ役ECサイト（猫ショップ）。9種の脆弱性をプラグイン方式で組込 |
| `agent/` | Python / FastAPI + Gemini | 偵察→照合→攻撃→修復→承認→再チェック。進行を SSE 配信 |
| `frontend/` | Next.js (TS) + D3-force | ダッシュボード（侵入マップ・思考ログ・ループ状況・承認バー） |

いずれも Google Cloud Run に公開（ハッカソン必須プロダクトを充足）。外部脆弱性DB（CVE/NVD）以外はすべて Google Cloud 内。

## エージェント API

- `POST /diagnose` — 診断開始（対象URLを受け取り、許可リスト検査を必ず通す）
- `GET /stream/{id}` — 進行イベントを SSE 配信（ノード更新・ログ行・ループ状況）
- `POST /approve/{id}` — 修正適用の承認を受ける（人間の承認フロー）

## 自己修復ループ

1. **攻撃** — やられ役サイトに侵入し脆弱性を突いて情報を抜く
2. **原因特定** — なぜ突破できたかを判断し原因コード箇所を特定
3. **修復案生成** — 安全な書き方のコードを Gemini で生成
4. **承認** — 「ここをこう直します」を人間に提示し承認を得て適用
5. **再攻撃で証明** — 同じ攻撃を再実行し、弾かれることを実証

### 修正の適用方式（2モード・`FIX_MODE`）

| モード | 誰がどう直すか | 稼働環境 |
|---|---|---|
| `flag`（既定） | やられ役サイトのランタイム状態を `control/patch` で切替。agent↔target は HTTP だけ | **分離構成でも可**（現 Cloud Run の公開デモはこれ） |
| `file` | **agent がリポジトリの実ソース（`target/lib/vulns/<id>.ts`）を直接書き換え**、HMR で反映。現実の「診断側がコードを直す」流れに近い | **ソース共有が必要**（ローカル／モノレポ）。`TARGET_REPO` を設定 |

`file` モードでは target は自己改変せず、ただ `next dev`（HMR）で動くだけ。修正するのは診断側（agent）で、`control/reset` 時に元の脆弱ソースへ復元する。

## 組み込む脆弱性（プラグイン方式・現在9種）

SQLインジェクション（CWE-89）/ XSS（CWE-79）/ 認証の甘さ（CWE-330）/ アクセス制御の不備（CWE-639）/ 設定ミス（CWE-200）/ パストラバーサル（CWE-22）/ コマンドインジェクション（CWE-78）/ JWT改ざん・alg=none（CWE-347）/ SSRF（CWE-918）

各脆弱性は **1プラグイン = 1定義** で管理する。エージェント側は `agent/plugins.py` に
「メタ情報・CWE/OWASP・攻撃の実行と成功判定・修正差分・侵入マップ表示」を 1 箇所へ集約し、
攻撃・照合・修復・ループはそこを参照するだけ。やられ役サイト側は `target/lib/vulns/<id>.ts`
に `isVulnerable(id)` で脆弱経路／安全経路を分岐する実装を置く。新しい脆弱性の追加は、
この 2 箇所にエントリを足すだけで済む。

## ローカル起動

```bash
# やられ役サイト
cd target && npm install && npm run dev        # http://localhost:3001

# エージェント
cd agent && python3 -m venv .venv && . .venv/bin/activate \
  && pip install -r requirements.txt && uvicorn main:app --reload --port 8000

# ダッシュボード
cd frontend && npm install && npm run dev       # http://localhost:3000
```

環境変数は各アプリの `.env.example` を参照。

## デプロイ（Cloud Run）

やられ役サイト → エージェント → フロントの順でデプロイし、環境変数でURLをつなぐ。手順の詳細は [`docs/DEPLOY.md`](docs/DEPLOY.md) を参照（target は状態がメモリ内のため `--max-instances 1` が必須）。
