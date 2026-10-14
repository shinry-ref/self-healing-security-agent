// 制御エンドポイント（脆弱性のリセット／修正適用）の認可。
// エージェントだけが共有シークレットを知っている前提で、x-control-token を検証する。
// これは「やられ役サイトの楽屋裏」を外部から叩かせないための仕切り。

export const CONTROL_TOKEN =
  process.env.CONTROL_TOKEN || "antibody-dev-control";

export function checkControlToken(req: Request): boolean {
  return req.headers.get("x-control-token") === CONTROL_TOKEN;
}
