import { isVulnerable } from "./registry";

// SSRF（サーバサイドリクエストフォージェリ）の実演ポイント（URL取り込み）。
//
// 脆弱版: ユーザーが渡した URL をサーバがそのまま取得する。攻撃者は
//   `http://169.254.169.254/...`（クラウドのメタデータ）や内部サービスの
//   URL を指定して、本来外から触れない機密を奪える。
// 安全版: 宛先ホストを検査し、内部・プライベート・メタデータ宛先を遮断する。
//
// 実際には外部へ通信せず、デモ用の疑似ネットワーク（すべてダミー）で再現する。

// サーバだけが到達できる「内部」エンドポイントの疑似応答（すべてダミー）。
const INTERNAL_RESPONSES: Record<string, string> = {
  "169.254.169.254":
    '{"AccessKeyId":"ASIA-DEMO-NEKO","SecretAccessKey":"antibody-demo-secret-key","Token":"demo-session-token"}',
  localhost: '{"service":"internal-admin","note":"NEKO MART internal only"}',
  "127.0.0.1": '{"service":"internal-admin","note":"NEKO MART internal only"}',
  "metadata.internal": '{"db_password":"neko-super-secret"}',
};

// 外から取り込んでよい公開先（デモ用の疑似応答）。
const PUBLIC_RESPONSES: Record<string, string> = {
  "images.neko-mart.example": '{"ok":true,"type":"image/png","bytes":20480}',
  "cdn.neko-mart.example": '{"ok":true,"cached":true}',
};

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function isInternalHost(host: string): boolean {
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "169.254.169.254" ||
    host.endsWith(".internal") ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  );
}

export interface FetchResult {
  ok: boolean;
  status: number;
  body?: string;
  reason?: string;
}

export function fetchUrl(url: string): FetchResult {
  const host = hostOf(url);
  if (!host) return { ok: false, status: 400, reason: "URL が不正です" };

  if (isVulnerable("ssrf")) {
    // 宛先を検査せずそのまま取得する（危険）。内部宛先にも到達してしまう。
    if (INTERNAL_RESPONSES[host]) {
      return { ok: true, status: 200, body: INTERNAL_RESPONSES[host] };
    }
    if (PUBLIC_RESPONSES[host]) {
      return { ok: true, status: 200, body: PUBLIC_RESPONSES[host] };
    }
    return { ok: true, status: 200, body: '{"ok":true,"note":"fetched (demo)"}' };
  }

  // 安全版: 内部・プライベート・メタデータ宛先を遮断する。
  if (isInternalHost(host)) {
    return { ok: false, status: 403, reason: "内部アドレスへの取得は禁止されています" };
  }
  if (PUBLIC_RESPONSES[host]) {
    return { ok: true, status: 200, body: PUBLIC_RESPONSES[host] };
  }
  return { ok: true, status: 200, body: '{"ok":true,"note":"fetched (demo)"}' };
}
