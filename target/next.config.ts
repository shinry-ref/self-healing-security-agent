import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // やられ役サイトは API ルートで DB を直叩きし、動的に描画する。
  // Next 16 既定の cacheComponents / partialPrefetching はキャッシュ前提で
  // 動的データに Suspense 境界を要求するため、デモの単純さを優先して無効化する。
  cacheComponents: false,
  partialPrefetching: false,
  // better-sqlite3 はネイティブモジュール。バンドルせずサーバ側で require させる。
  serverExternalPackages: ["better-sqlite3"],
  turbopack: {
    root: import.meta.dirname,
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
