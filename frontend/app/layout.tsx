import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "アンチボディ — 脆弱性の自動診断ツール",
  description:
    "AIエージェントが自作のやられ役サイトへ本物の侵入を仕掛け、原因を塞ぎ、再攻撃で防御を証明する自己修復型セキュリティ診断ツール",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
