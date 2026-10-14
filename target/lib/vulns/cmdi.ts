import { isVulnerable } from "./registry";

// コマンドインジェクションの実演ポイント（ネットワーク診断ツール）。
//
// 脆弱版: ユーザー入力の host を `sh -c "ping -c1 <host>"` のように OS コマンドへ
//   連結する実装を模す。`localhost; id` のようにシェルのメタ文字を混ぜると、
//   追加コマンドが実行されてしまう。
// 安全版: シェルを介さず、host をホスト名として厳格に検証する。メタ文字を含む
//   入力は拒否する。
//
// 実際には OS シェルを起動せず、デモ用の安全な「疑似コマンド実行器」で
// 注入が成立したことだけを再現する（任意コマンドは一切実行しない）。

// 注入された疑似コマンドに対する、決め打ちのダミー出力。
function fakeCommandOutput(cmd: string): string {
  const c = cmd.trim();
  if (/^id\b/.test(c)) return "uid=0(root) gid=0(root) groups=0(root)";
  if (/^whoami\b/.test(c)) return "root";
  if (/^cat\s+\/etc\/passwd/.test(c))
    return "root:x:0:0:root:/root:/bin/bash\nneko:x:1000:1000::/home/neko:/bin/sh";
  if (/^ls\b/.test(c)) return "app  node_modules  package.json  secret";
  return `sh: ${c}: executed (demo)`;
}

const SHELL_META = /[;&|`$(){}<>\n]/;

export interface ToolResult {
  ok: boolean;
  output: string;
  injected: boolean;
}

export function runNetTool(host: string): ToolResult {
  if (isVulnerable("cmdi")) {
    // 入力をシェル文字列へ連結したのと同じ状況を再現する（危険）。
    const parts = host.split(/\s*(?:;|&&|\|\||\||&)\s*/).filter(Boolean);
    const target = parts.shift() || host;
    const lines = [`PING ${target}: 56 data bytes`, `64 bytes from ${target}: icmp_seq=0 ttl=64 time=0.1 ms`];
    let injected = false;
    for (const extra of parts) {
      // ping 以外に紛れ込んだコマンドが「実行」される
      injected = true;
      lines.push(fakeCommandOutput(extra));
    }
    return { ok: true, output: lines.join("\n"), injected };
  }

  // 安全版: ホスト名として妥当な文字だけ許可。メタ文字を含むなら拒否。
  if (SHELL_META.test(host) || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    return { ok: false, output: "不正なホスト名です", injected: false };
  }
  return {
    ok: true,
    output: `PING ${host}: 56 data bytes\n64 bytes from ${host}: icmp_seq=0 ttl=64 time=0.1 ms`,
    injected: false,
  };
}
