import { isVulnerable } from "./registry";

// アクセス制御の不備（IDOR）の実演ポイント（注文履歴の参照）。
//
// 脆弱版: 注文IDさえ分かれば所有者チェックなしで誰の注文でも読める。
//   `/api/orders/1001` → `/api/orders/1002` と ID を変えると他人の情報が見える。
// 安全版: 要求者が注文の所有者（または管理者）であることを確認する。

export interface OrderOwnerInfo {
  orderUserId: number;
  requesterUserId: number | null;
  requesterRole: string | null;
}

export function canReadOrder(info: OrderOwnerInfo): boolean {
  if (isVulnerable("access")) {
    return true; // 誰でも読めてしまう（危険）
  }
  if (info.requesterUserId === null) return false;
  if (info.requesterRole === "admin") return true;
  return info.orderUserId === info.requesterUserId;
}
