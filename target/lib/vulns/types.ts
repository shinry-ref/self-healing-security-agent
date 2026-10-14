// やられ役サイトに仕込む脆弱性の種類と、その実行時状態を表す型。
// 攻撃対象（enabled）であり、まだ修正されていない（!patched）とき「脆弱」。

export type VulnId = "sqli" | "xss" | "auth" | "access" | "misconfig";

export const ALL_VULNS: VulnId[] = [
  "sqli",
  "xss",
  "auth",
  "access",
  "misconfig",
];

export type Severity = "high" | "medium" | "low";

export interface VulnMeta {
  id: VulnId;
  /** 日本語の脆弱性名 */
  name: string;
  /** 仕込む場所の例 */
  location: string;
  /** 攻撃のされ方 */
  attack: string;
  /** 直し方 */
  fix: string;
  severity: Severity;
  /** エージェントが攻撃する主なエンドポイント */
  endpoint: string;
}
