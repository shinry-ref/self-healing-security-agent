"use client";

import { useState } from "react";

export default function AdminPage() {
  const [result, setResult] = useState<string | null>(null);

  async function fetchDebug() {
    const res = await fetch("/api/debug");
    const data = await res.json();
    setResult(JSON.stringify(data, null, 2));
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="mb-2 text-2xl font-bold">管理コンソール</h1>
      <p className="mb-6 text-sm text-zinc-500">
        内部のデバッグ情報を表示します（設定次第で公開範囲が変わります）。
      </p>
      <button
        onClick={fetchDebug}
        className="rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700"
      >
        /api/debug を表示
      </button>
      {result && (
        <pre className="mt-4 overflow-auto rounded-lg bg-zinc-100 p-3 text-xs">{result}</pre>
      )}
    </div>
  );
}
