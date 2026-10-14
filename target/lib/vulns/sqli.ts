import { getDb } from "../db";
import { isVulnerable } from "./registry";

export interface UserRow {
  id: number;
  username: string;
  password: string;
  role: string;
  email: string;
  credit_card: string;
}

/**
 * ログイン認証。SQLインジェクションの実演ポイント。
 *
 * 脆弱版: 入力を SQL 文字列へそのまま連結する。`admin' --` や
 *   `' OR '1'='1` でWHERE句が無効化され、パスワード無しでログインできる。
 * 安全版: プレースホルダ（プリペアドステートメント）で入力を分離する。
 */
export function authenticate(
  username: string,
  password: string
): { user: UserRow | null; sqlUsed: string } {
  const db = getDb();

  if (isVulnerable("sqli")) {
    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    try {
      const user = db.prepare(sql).get() as UserRow | undefined;
      return { user: user ?? null, sqlUsed: sql };
    } catch {
      // 壊れたSQLでも落とさず「失敗」として扱う
      return { user: null, sqlUsed: sql };
    }
  }

  const sql = "SELECT * FROM users WHERE username = ? AND password = ?";
  const user = db.prepare(sql).get(username, password) as UserRow | undefined;
  return { user: user ?? null, sqlUsed: `${sql}  -- params: [${username}, ***]` };
}
