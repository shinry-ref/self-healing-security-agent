import { isVulnerable } from "./registry";

// パストラバーサル（ディレクトリトラバーサル）の実演ポイント（ファイル取得）。
//
// 脆弱版: 要求されたファイル名を公開ディレクトリへそのまま連結し、`../` による
//   上位ディレクトリへの脱出を許す。`?name=../secret/credentials.txt` で
//   公開範囲外の機密ファイルを読めてしまう。
// 安全版: ファイル名を basename（パス区切りを含まない）に限定し、公開
//   ディレクトリの中だけを参照する。
//
// 実ファイルシステムは触らず、デモ用の仮想ファイルツリー（すべてダミー）で再現する。

const VFS: Record<string, string> = {
  "public/readme.txt": "NEKO MART 商品ダウンロードセンターへようこそ。",
  "public/catalog.txt": "公開カタログ: キャットタワー / 爪とぎ / 自動給餌器",
  // 公開ディレクトリの外に置かれた、本来読めてはいけない機密（すべてダミー）。
  "secret/credentials.txt":
    "# NEKO MART internal (demo)\nDB_PASSWORD=neko-super-secret\nADMIN_TOKEN=antibody-demo-admin-token\n",
};

const PUBLIC_DIR = "public/";

/** `public/` を基点に `..` を解決する（脆弱版が使う。脱出を防がない）。 */
function resolveUnsafe(name: string): string {
  const parts = (PUBLIC_DIR + name).split("/");
  const stack: string[] = [];
  for (const p of parts) {
    if (p === "" || p === ".") continue;
    if (p === "..") stack.pop();
    else stack.push(p);
  }
  return stack.join("/");
}

export interface FileResult {
  ok: boolean;
  path: string;
  content?: string;
}

export function readUserFile(name: string): FileResult {
  if (isVulnerable("pathtraversal")) {
    // `../` を解決してしまうため、公開ディレクトリの外へ出られる（危険）。
    const path = resolveUnsafe(name);
    const content = VFS[path];
    return content !== undefined
      ? { ok: true, path, content }
      : { ok: false, path };
  }

  // 安全版: パス区切りを捨てて basename だけにし、公開ディレクトリ内に閉じ込める。
  const base = name.split(/[\\/]/).pop() || "";
  const path = PUBLIC_DIR + base;
  const content = VFS[path];
  return content !== undefined
    ? { ok: true, path, content }
    : { ok: false, path };
}
