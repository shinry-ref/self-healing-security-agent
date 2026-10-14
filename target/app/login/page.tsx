"use client";

import { useState } from "react";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setResult(null);
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.ok) {
      setResult(`ログイン成功: ${data.user.username}（${data.user.role}） / token=${data.token}`);
    } else {
      setResult(`失敗: ${data.error}`);
    }
  }

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="mb-6 text-2xl font-bold">ログイン</h1>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="mb-1 block text-sm text-zinc-600">ユーザー名</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-lg border border-zinc-300 px-3 py-2"
            placeholder="tanaka"
          />
        </div>
        <div>
          <label className="mb-1 block text-sm text-zinc-600">パスワード</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-zinc-300 px-3 py-2"
            placeholder="••••••"
          />
        </div>
        <button
          type="submit"
          className="w-full rounded-lg bg-zinc-900 px-4 py-2 font-medium text-white hover:bg-zinc-700"
        >
          ログイン
        </button>
      </form>
      {result && (
        <pre className="mt-4 whitespace-pre-wrap break-all rounded-lg bg-zinc-100 p-3 text-xs">
          {result}
        </pre>
      )}
    </div>
  );
}
