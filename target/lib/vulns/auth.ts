import { randomBytes, createHmac } from "crypto";
import { isVulnerable } from "./registry";

// セッショントークンの発行・検証。「認証の甘さ」の実演ポイント。
//
// 脆弱版: トークンが `user-<id>` という推測可能な形式。ログインせずとも
//   `user-1`（管理者）を名乗れば検証を通ってしまう（なりすまし可能）。
// 安全版: 乱数＋HMAC署名のトークンのみを受理し、改ざん・推測を弾く。

declare global {
  // eslint-disable-next-line no-var
  var __mamoriTokenStore: Map<string, number> | undefined;
}

function store(): Map<string, number> {
  if (!globalThis.__mamoriTokenStore) globalThis.__mamoriTokenStore = new Map();
  return globalThis.__mamoriTokenStore;
}

const SIGNING_KEY =
  process.env.SESSION_SIGNING_KEY || "mamori-demo-signing-key-change-me";

function sign(raw: string): string {
  return createHmac("sha256", SIGNING_KEY).update(raw).digest("hex").slice(0, 32);
}

/** ログイン成功時にトークンを発行する。 */
export function issueToken(userId: number): string {
  if (isVulnerable("auth")) {
    // 推測可能なトークン（弱い設計）
    const token = `user-${userId}`;
    store().set(token, userId);
    return token;
  }
  const rnd = randomBytes(16).toString("hex");
  const raw = `${userId}.${rnd}`;
  const token = `sess_${raw}.${sign(raw)}`;
  store().set(token, userId);
  return token;
}

/** トークンを検証し、ユーザーIDを返す（不正なら null）。 */
export function verifyToken(token: string | null | undefined): number | null {
  if (!token) return null;

  if (isVulnerable("auth")) {
    // 推測可能な形式を、発行履歴の有無に関わらず受理してしまう
    const m = /^user-(\d+)$/.exec(token);
    if (m) return Number(m[1]);
    return store().get(token) ?? null;
  }

  // 安全版: 署名を検証し、かつ発行済みのものだけ受理
  const m = /^sess_(\d+\.[0-9a-f]+)\.([0-9a-f]{32})$/.exec(token);
  if (!m) return null;
  if (sign(m[1]) !== m[2]) return null;
  if (!store().has(token)) return null;
  return Number(m[1].split(".")[0]);
}

/** Authorization ヘッダ（Bearer）からトークンを取り出す。 */
export function bearerFrom(req: Request): string | null {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}
