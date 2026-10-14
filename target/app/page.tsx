import Link from "next/link";
import { getDb } from "@/lib/db";

export const dynamic = "force-dynamic";

interface Product {
  id: number;
  name: string;
  price: number;
  description: string;
  emoji: string;
}

export default function Home() {
  const db = getDb();
  const products = db
    .prepare("SELECT id, name, price, description, emoji FROM products")
    .all() as Product[];

  return (
    <div>
      <h1 className="mb-6 text-2xl font-bold">猫グッズ一覧</h1>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {products.map((p) => (
          <Link
            key={p.id}
            href={`/products/${p.id}`}
            className="rounded-xl border border-zinc-200 bg-white p-5 transition hover:border-zinc-400 hover:shadow-sm"
          >
            <div className="mb-3 text-5xl">{p.emoji}</div>
            <div className="font-semibold">{p.name}</div>
            <div className="mt-1 text-sm text-zinc-500">{p.description}</div>
            <div className="mt-3 text-lg font-bold text-rose-600">
              ¥{p.price.toLocaleString()}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
