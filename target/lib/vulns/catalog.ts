import type { VulnMeta, VulnId } from "./types";

// 要件定義の「組み込む5脆弱性」テーブルと一対一に対応するカタログ。
// エージェント側（Python）にも同じ語彙の写しがあり、両者で突き合わせる。
export const CATALOG: Record<VulnId, VulnMeta> = {
  sqli: {
    id: "sqli",
    name: "SQLインジェクション",
    location: "ログイン、商品検索",
    attack: "入力をSQL文にそのまま連結",
    fix: "プレースホルダで入力を分離",
    severity: "high",
    endpoint: "POST /api/login",
  },
  xss: {
    id: "xss",
    name: "XSS",
    location: "レビュー投稿、問い合わせ",
    attack: "入力を無加工で画面に出力",
    fix: "出力時にエスケープ",
    severity: "high",
    endpoint: "POST /api/products/[id]/reviews",
  },
  auth: {
    id: "auth",
    name: "認証の甘さ",
    location: "ログイン、セッション",
    attack: "推測可能なトークン、弱い検証",
    fix: "強いトークン・検証を追加",
    severity: "high",
    endpoint: "GET /api/me",
  },
  access: {
    id: "access",
    name: "アクセス制御の不備",
    location: "注文履歴、マイページ",
    attack: "IDを変えると他人の情報が見える",
    fix: "所有者チェックを追加",
    severity: "high",
    endpoint: "GET /api/orders/[id]",
  },
  misconfig: {
    id: "misconfig",
    name: "設定ミス",
    location: "管理画面、設定ファイル",
    attack: "公開すべきでない情報が露出",
    fix: "公開範囲を制限",
    severity: "medium",
    endpoint: "GET /api/debug",
  },
  pathtraversal: {
    id: "pathtraversal",
    name: "パストラバーサル",
    location: "ファイル取得",
    attack: "?name=../ でサーバ内の任意ファイルを読む",
    fix: "ファイル名を basename に限定し公開ディレクトリ内へ閉じ込める",
    severity: "high",
    endpoint: "GET /api/files",
  },
  cmdi: {
    id: "cmdi",
    name: "コマンドインジェクション",
    location: "ネットワーク診断ツール",
    attack: "入力を OS コマンドへ連結し任意コマンドを実行",
    fix: "シェルを介さず入力を厳格に検証する",
    severity: "high",
    endpoint: "GET /api/net-tool",
  },
  jwt: {
    id: "jwt",
    name: "JWT改ざん（alg=none）",
    location: "APIセッション",
    attack: "alg=none の署名なしトークンで権限昇格",
    fix: "alg=none を拒否し HS256 署名を必須にする",
    severity: "high",
    endpoint: "GET /api/session",
  },
  ssrf: {
    id: "ssrf",
    name: "SSRF",
    location: "URL取り込み",
    attack: "内部アドレスへリクエストを向けさせ機密を奪う",
    fix: "内部・プライベート宛先を遮断し許可リストに限定する",
    severity: "high",
    endpoint: "GET /api/fetch",
  },
};

export function metaOf(id: VulnId): VulnMeta {
  return CATALOG[id];
}
