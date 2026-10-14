import { isVulnerable } from "./registry";

// 格納型XSSの実演ポイント（レビュー投稿）。
//
// 脆弱版: 投稿本文を無加工のまま画面に出力する。`<script>...</script>` が
//   実行される。
// 安全版: 出力時に HTML エスケープしてから表示する。

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** レビュー本文を画面表示用（HTML文字列）に変換する。 */
export function renderReviewBody(body: string): string {
  if (isVulnerable("xss")) {
    return body; // 無加工でそのまま出力（危険）
  }
  return escapeHtml(body);
}
