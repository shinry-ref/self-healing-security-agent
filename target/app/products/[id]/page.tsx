"use client";

import { use, useCallback, useEffect, useState } from "react";

interface Product {
  id: number;
  name: string;
  price: number;
  description: string;
  emoji: string;
}
interface Review {
  id: number;
  author: string;
  created_at: string;
  body_html: string;
}

export default function ProductPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [product, setProduct] = useState<Product | null>(null);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [author, setAuthor] = useState("");
  const [body, setBody] = useState("");

  const load = useCallback(async () => {
    const [p, r] = await Promise.all([
      fetch(`/api/products/${id}`).then((x) => x.json()),
      fetch(`/api/products/${id}/reviews`).then((x) => x.json()),
    ]);
    setProduct(p.product ?? null);
    setReviews(r.reviews ?? []);
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function postReview(e: React.FormEvent) {
    e.preventDefault();
    await fetch(`/api/products/${id}/reviews`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ author: author || "匿名", body }),
    });
    setBody("");
    setAuthor("");
    load();
  }

  if (!product) return <div>読み込み中…</div>;

  return (
    <div className="mx-auto max-w-2xl">
      <div className="mb-8 flex items-center gap-6">
        <div className="text-7xl">{product.emoji}</div>
        <div>
          <h1 className="text-2xl font-bold">{product.name}</h1>
          <p className="mt-1 text-zinc-500">{product.description}</p>
          <p className="mt-2 text-xl font-bold text-rose-600">
            ¥{product.price.toLocaleString()}
          </p>
        </div>
      </div>

      <h2 className="mb-3 text-lg font-semibold">レビュー</h2>
      <div className="space-y-3">
        {reviews.map((r) => (
          <div key={r.id} className="rounded-lg border border-zinc-200 bg-white p-4">
            <div className="mb-1 text-sm font-medium">{r.author}</div>
            {/* 診断デモのため body を出力処理の結果そのまま描画する。
                脆弱版では無加工（格納型XSSが成立）、安全版ではエスケープ済み。 */}
            <div
              className="text-sm text-zinc-700"
              dangerouslySetInnerHTML={{ __html: r.body_html }}
            />
          </div>
        ))}
        {reviews.length === 0 && (
          <p className="text-sm text-zinc-400">まだレビューはありません。</p>
        )}
      </div>

      <form onSubmit={postReview} className="mt-6 space-y-3 rounded-lg border border-zinc-200 bg-white p-4">
        <input
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="お名前"
          className="w-full rounded border border-zinc-300 px-3 py-2 text-sm"
        />
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="レビューを書く"
          className="w-full rounded border border-zinc-300 px-3 py-2 text-sm"
          rows={3}
        />
        <button className="rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700">
          投稿する
        </button>
      </form>
    </div>
  );
}
