"use client";

import { useState } from "react";

export default function MyPage() {
  const [token, setToken] = useState("");
  const [orderId, setOrderId] = useState("1001");
  const [result, setResult] = useState<string | null>(null);

  async function fetchOrder() {
    const res = await fetch(`/api/orders/${orderId}`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    const data = await res.json();
    setResult(JSON.stringify(data, null, 2));
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="mb-2 text-2xl font-bold">マイページ（注文照会）</h1>
      <p className="mb-6 text-sm text-zinc-500">
        注文番号を入れて照会します。ログインで得たトークンを入れてください。
      </p>
      <div className="space-y-3">
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="トークン（Bearer）"
          className="w-full rounded border border-zinc-300 px-3 py-2 text-sm"
        />
        <input
          value={orderId}
          onChange={(e) => setOrderId(e.target.value)}
          placeholder="注文番号 (例: 1001)"
          className="w-full rounded border border-zinc-300 px-3 py-2 text-sm"
        />
        <button
          onClick={fetchOrder}
          className="rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700"
        >
          注文を照会
        </button>
      </div>
      {result && (
        <pre className="mt-4 overflow-auto rounded-lg bg-zinc-100 p-3 text-xs">{result}</pre>
      )}
    </div>
  );
}
