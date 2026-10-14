import { getDb } from "../db";
import { isVulnerable } from "./registry";
import type { UserRow } from "./sqli";

// 設定ミスの実演ポイント（デバッグ用エンドポイントの公開忘れ）。
//
// 脆弱版: 認証なしの `/api/debug` が、環境変数・内部設定・全ユーザー情報
//   （パスワードやカード番号を含む）を丸ごと返してしまう。
// 安全版: そもそも公開しない（403）。

export interface DebugExposure {
  exposed: boolean;
  data?: {
    note: string;
    env: Record<string, string>;
    users: UserRow[];
  };
}

export function debugExposure(): DebugExposure {
  if (!isVulnerable("misconfig")) {
    return { exposed: false };
  }

  const db = getDb();
  const users = db.prepare("SELECT * FROM users").all() as UserRow[];
  return {
    exposed: true,
    data: {
      note: "DEBUG ENDPOINT — 本番で絶対に公開してはいけない内部情報",
      env: {
        NODE_ENV: process.env.NODE_ENV || "development",
        SESSION_SIGNING_KEY:
          process.env.SESSION_SIGNING_KEY || "mamori-demo-signing-key-change-me",
        DB_CONNECTION: "sqlite://:memory: (NEKO MART internal)",
      },
      users, // パスワード・カード番号を含む全ユーザー（ダミー）
    },
  };
}
