import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // ダッシュボードは SSE を中継し、診断結果をリアルタイム描画する。
  // キャッシュ前提の挙動を避けるため Next 16 の新既定を無効化する。
  cacheComponents: false,
  partialPrefetching: false,
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
