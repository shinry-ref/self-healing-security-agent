import Dashboard from "@/components/Dashboard";

// 実行時の環境変数（Cloud Run の --set-env-vars）をサーバー側で読み、クライアントへ渡す。
// NEXT_PUBLIC_* はビルド時に焼き込まれてしまうため、サーバーコンポーネント経由にする。
export const dynamic = "force-dynamic";

export default function Home() {
  const agentUrl = process.env.AGENT_URL || "http://localhost:8000";
  const defaultTarget = process.env.TARGET_URL || "http://localhost:3001";
  return <Dashboard agentUrl={agentUrl} defaultTarget={defaultTarget} />;
}
