import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "NEKO MART（診断デモ用・脆弱サイト）",
  description: "まもり の診断対象となる、わざと脆弱にした猫グッズECサイト",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ja">
      <body className="min-h-screen bg-zinc-50 text-zinc-900 antialiased">
        {/* 合法性の明示: この対象がデモ用のやられ役サイトであることを全画面で告知 */}
        <div className="w-full bg-amber-500 px-4 py-1.5 text-center text-xs font-medium text-amber-950">
          ⚠️ これは「まもり」の診断対象として、わざと脆弱に作られたデモ用サイトです。実在の店舗・個人情報ではありません。
        </div>
        <header className="border-b border-zinc-200 bg-white">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <Link href="/" className="flex items-center gap-2 text-lg font-bold">
              <span className="text-2xl">🐱</span> NEKO MART
            </Link>
            <nav className="flex gap-4 text-sm text-zinc-600">
              <Link href="/" className="hover:text-zinc-900">商品</Link>
              <Link href="/mypage" className="hover:text-zinc-900">マイページ</Link>
              <Link href="/admin" className="hover:text-zinc-900">管理</Link>
              <Link href="/login" className="hover:text-zinc-900">ログイン</Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-5xl px-4 py-8">{children}</main>
      </body>
    </html>
  );
}
