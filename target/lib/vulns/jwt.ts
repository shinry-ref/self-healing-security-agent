import { createHmac, timingSafeEqual } from "crypto";
import { isVulnerable } from "./registry";

// JWT 改ざん（alg=none）の実演ポイント（API セッション）。
//
// 脆弱版: トークンの header.alg が "none" のとき署名検証を省き、payload を
//   そのまま信頼する。攻撃者は {"alg":"none"} のヘッダと {"role":"admin"} の
//   payload を自作するだけで管理者になりすませる。
// 安全版: alg=none を拒否し、HS256 の署名検証に通ったトークンだけを受理する。

const JWT_KEY =
  process.env.SESSION_SIGNING_KEY || "antibody-demo-signing-key-change-me";

function b64urlDecode(s: string): string {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function hs256(signingInput: string): string {
  return b64url(createHmac("sha256", JWT_KEY).update(signingInput).digest());
}

export interface JwtClaims {
  sub?: number | string;
  role?: string;
  username?: string;
}

export interface JwtResult {
  ok: boolean;
  claims?: JwtClaims;
  reason?: string;
}

/** HS256 で署名した正規トークンを発行する（安全版ログインなどが使う想定）。 */
export function signSession(claims: JwtClaims): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify(claims));
  const input = `${header}.${payload}`;
  return `${input}.${hs256(input)}`;
}

export function verifySession(token: string | null | undefined): JwtResult {
  if (!token) return { ok: false, reason: "トークンがありません" };
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "形式が不正です" };

  let header: { alg?: string };
  let claims: JwtClaims;
  try {
    header = JSON.parse(b64urlDecode(parts[0]));
    claims = JSON.parse(b64urlDecode(parts[1]));
  } catch {
    return { ok: false, reason: "デコードに失敗しました" };
  }

  if (isVulnerable("jwt")) {
    // alg=none を信頼してしまう（危険）。署名を検証しない。
    if ((header.alg || "").toLowerCase() === "none") {
      return { ok: true, claims };
    }
    // HS256 の場合は一応検証する
    const input = `${parts[0]}.${parts[1]}`;
    if (parts[2] === hs256(input)) return { ok: true, claims };
    return { ok: false, reason: "署名が一致しません" };
  }

  // 安全版: alg=none を明確に拒否し、HS256 の署名を必須にする。
  if ((header.alg || "").toLowerCase() !== "hs256") {
    return { ok: false, reason: "許可されていない alg です" };
  }
  const input = `${parts[0]}.${parts[1]}`;
  const expected = hs256(input);
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: "署名検証に失敗しました" };
  }
  return { ok: true, claims };
}
