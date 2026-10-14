# デプロイ手順（Google Cloud Run）

「アンチボディ」を Cloud Run に公開するための手順です。**やられ役サイト → エージェント → ダッシュボード** の順にデプロイし、環境変数で URL を相互に繋ぎます。外部に出るのは脆弱性DB（CVE/NVD）照合のみで、それ以外はすべて Google Cloud 内で完結します。

## 前提

- `gcloud` CLI がインストール済み・ログイン済み（`gcloud auth login`）
- 課金有効なプロジェクトを選択済み（`gcloud config set project <PROJECT_ID>`）
- 必要 API を有効化：

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
```

以降は共通の変数を使います。

```bash
PROJECT=$(gcloud config get-value project)
REGION=asia-northeast1          # 東京。好みで変更可
CONTROL_TOKEN=$(openssl rand -hex 16)   # agent と target で共有する秘密
SIGNING_KEY=$(openssl rand -hex 16)     # target のセッション署名鍵
```

> `CONTROL_TOKEN` は **agent と target で必ず同じ値**にします。これが「やられ役サイトの楽屋裏（reset/patch/state）」を外部から叩かせないための仕切りです。

---

## 1. やられ役サイト（target）

`--max-instances=1` が**必須**です。target は脆弱性の有効/修正状態と疑似DB（`:memory:` SQLite）を**インスタンスのメモリ内**に保持するため、攻撃 → 修正適用 → 再攻撃が同一インスタンスに届かないとループが壊れます。

```bash
cd target
gcloud run deploy antibody-target \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --max-instances 1 \
  --set-env-vars "CONTROL_TOKEN=${CONTROL_TOKEN},SESSION_SIGNING_KEY=${SIGNING_KEY}"

TARGET_URL=$(gcloud run services describe antibody-target --region "$REGION" --format='value(status.url)')
echo "TARGET_URL=$TARGET_URL"
```

- ポートは Cloud Run が `$PORT` を注入し、Dockerfile の `next start` が拾います。
- `--allow-unauthenticated`：エージェントとブラウザが直接アクセスするため公開必須。中身は全てダミーの架空データで、画面上部にも「診断用のやられ役サイト」と常時明示されます。

---

## 2. エージェント（agent）

```bash
cd ../agent
gcloud run deploy antibody-agent \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "ALLOWED_TARGETS=${TARGET_URL},CONTROL_TOKEN=${CONTROL_TOKEN}"

AGENT_URL=$(gcloud run services describe antibody-agent --region "$REGION" --format='value(status.url)')
echo "AGENT_URL=$AGENT_URL"
```

- **`ALLOWED_TARGETS` が合法性の要**。ここに完全一致で載った URL しか診断しません（前方一致・部分一致なし、`http`/`https` 以外も拒否）。載っていない相手は `403` で弾きます。複数指定はカンマ区切り。
- **Gemini（任意）**：原因特定・修正コード生成に使います。未設定でも実コード対応のフォールバック差分でループは完結します（スモークテスト済み）。使う場合は Secret Manager 経由を推奨：

```bash
echo -n "<YOUR_GEMINI_API_KEY>" | gcloud secrets create gemini-api-key --data-file=-
gcloud run services update antibody-agent --region "$REGION" \
  --update-secrets "GEMINI_API_KEY=gemini-api-key:latest" \
  --update-env-vars "GEMINI_MODEL=gemini-2.5-flash"
```

- NVD も照合に加えるなら `--update-env-vars ENABLE_NVD=1`（デモは自前データ中心なので任意）。

---

## 3. ダッシュボード（frontend）

`AGENT_URL` と `TARGET_URL` はサーバーコンポーネントが**実行時**に読み、ブラウザへ渡します（`NEXT_PUBLIC_*` と違いビルド時に焼き込まれません）。ブラウザはこの `AGENT_URL` へ直接 SSE 購読・承認を送るため、**公開到達可能な URL** を入れてください。

```bash
cd ../frontend
gcloud run deploy antibody-frontend \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "AGENT_URL=${AGENT_URL},TARGET_URL=${TARGET_URL}"

FRONTEND_URL=$(gcloud run services describe antibody-frontend --region "$REGION" --format='value(status.url)')
echo "ダッシュボード: $FRONTEND_URL"
```

---

## 4. 疎通確認

```bash
# エージェントの健康診断（許可リストが見える）
curl -s "$AGENT_URL/health"
# → {"ok":true,"allowed":["https://antibody-target-xxxx.a.run.app"]}

# 許可リスト外は 403 で弾かれる（安全装置の確認）
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$AGENT_URL/diagnose" \
  -H 'content-type: application/json' -d '{"target":"http://example.com"}'
# → 403
```

ダッシュボードを開き「診断開始」を押すと、偵察 → 照合 → 攻撃 → 修復 → 承認 → 再証明のループが可視化されます。各脆弱性で「ここをこう直します」の承認バーが出るので、承認すると修正が適用され、同じ攻撃が弾かれることまで確認できます。

---

## 補足・運用上の注意

| 項目 | 内容 |
|---|---|
| target のインスタンス数 | **必ず `--max-instances 1`**。状態がメモリ内のため多重インスタンスでループが壊れる |
| SSE のタイムアウト | Cloud Run の既定リクエストタイムアウトは 300 秒。診断は通常これに収まるが、延ばす場合は `--timeout 600` |
| CORS | エージェントは `*` 許可済み（ダッシュボードから直接 SSE 購読するため） |
| コスト | デモ後は `gcloud run services delete antibody-target antibody-agent antibody-frontend --region "$REGION"` で削除 |
| 再デモ | ダッシュボードの診断開始時に target を自動 reset（全脆弱性を再有効化・DB 再シード）するため、連続デモ可能 |

## トラブルシュート

- **診断が途中で止まる** → target が `--max-instances 1` か確認。複数インスタンスだと patch と再攻撃が別インスタンスに届かず再証明に失敗する。
- **承認後も弾かれない** → agent/target の `CONTROL_TOKEN` 不一致。patch 呼び出しが認可されていない。両サービスの env を確認。
- **`403` で診断できない** → `ALLOWED_TARGETS` が target の実 URL と**完全一致**しているか（末尾スラッシュ・`http`/`https` の違いに注意）。
