"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import IntrusionMap from "./IntrusionMap";
import type {
  Approval,
  DiagnoseState,
  Graph,
  LogLine,
  LoopState,
  Report,
  Stats,
  StatusEvent,
} from "./types";

const EMPTY_GRAPH: Graph = { nodes: [], edges: [] };
const EMPTY_STATS: Stats = { found: 0, patched: 0, records: 0, depth: "—" };

const STATUS_LABEL: Record<DiagnoseState, string> = {
  idle: "待機中",
  recon: "偵察中",
  attacking: "侵入中",
  fixing: "修復中",
  awaiting_approval: "承認待ち",
  reproving: "再チェック中",
  done: "完了",
};

function statusTone(state: DiagnoseState): { bg: string; border: string; dot: string; text: string } {
  switch (state) {
    case "attacking":
    case "reproving":
      return { bg: "#2A1420", border: "#6E2438", dot: "#FF5571", text: "#FF8198" };
    case "fixing":
    case "awaiting_approval":
      return { bg: "#241B08", border: "#6E5524", dot: "#F3B64B", text: "#F3C877" };
    case "done":
      return { bg: "#0E2418", border: "#246E4A", dot: "#5FD08F", text: "#7FE0A8" };
    default:
      return { bg: "#152238", border: "#2C3850", dot: "#5ED1E6", text: "#9FE4F1" };
  }
}

const LOG_ACCENT: Record<LogLine["level"], { border: string; ts: string; text: string }> = {
  info: { border: "transparent", ts: "#56647E", text: "#B8C3D4" },
  active: { border: "#F3B64B", ts: "#F3B64B", text: "#EBD49B" },
  success: { border: "#FF5571", ts: "#FF8198", text: "#F2C6CF" },
  warn: { border: "#F3B64B", ts: "#B08E4C", text: "#D8C79A" },
};

export default function Dashboard({
  agentUrl,
  defaultTarget,
}: {
  agentUrl: string;
  defaultTarget: string;
}) {
  const AGENT_URL = agentUrl.replace(/\/$/, "");
  const [target, setTarget] = useState(defaultTarget.replace(/\/$/, ""));
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [status, setStatus] = useState<StatusEvent>({ state: "idle", round: 0, maxRounds: 0 });
  const [graph, setGraph] = useState<Graph>(EMPTY_GRAPH);
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [loop, setLoop] = useState<LoopState | null>(null);
  const [approval, setApproval] = useState<Approval | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [approving, setApproving] = useState(false);

  const esRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs]);

  useEffect(() => () => esRef.current?.close(), []);

  const nowTs = () => {
    const d = new Date();
    return `${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  const start = useCallback(async () => {
    esRef.current?.close();
    setStatus({ state: "recon", round: 0, maxRounds: 0 });
    setGraph(EMPTY_GRAPH);
    setStats(EMPTY_STATS);
    setLogs([]);
    setLoop(null);
    setApproval(null);
    setReport(null);
    setError(null);
    setShowDiff(false);

    let id: string;
    try {
      const res = await fetch(`${AGENT_URL}/diagnose`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `診断を開始できませんでした (${res.status})`);
      }
      id = (await res.json()).id;
    } catch (e) {
      setError(e instanceof Error ? e.message : "エージェントに接続できません");
      setStatus({ state: "idle", round: 0, maxRounds: 0 });
      return;
    }

    setSessionId(id);
    const es = new EventSource(`${AGENT_URL}/stream/${id}`);
    esRef.current = es;

    es.addEventListener("graph", (ev) => setGraph(JSON.parse((ev as MessageEvent).data)));
    es.addEventListener("stats", (ev) => setStats(JSON.parse((ev as MessageEvent).data)));
    es.addEventListener("status", (ev) => setStatus(JSON.parse((ev as MessageEvent).data)));
    es.addEventListener("loop", (ev) => setLoop(JSON.parse((ev as MessageEvent).data)));
    es.addEventListener("log", (ev) => {
      const line = JSON.parse((ev as MessageEvent).data);
      setLogs((prev) => [...prev, { ...line, ts: nowTs() }]);
    });
    es.addEventListener("approval", (ev) => {
      setApproval(JSON.parse((ev as MessageEvent).data));
      setShowDiff(false);
    });
    es.addEventListener("report", (ev) => setReport(JSON.parse((ev as MessageEvent).data)));
    es.addEventListener("error", (ev) => {
      // ネットワーク断は data を持たない（その場合は EventSource の自動再接続に任せる）
      const data = (ev as MessageEvent).data;
      if (data) {
        try {
          setError(JSON.parse(data).message);
        } catch {
          /* 無視 */
        }
      }
    });
    // 診断完了。サーバーがストリームを閉じる前に end で明示的に購読を止め、再接続を防ぐ。
    es.addEventListener("end", () => es.close());
  }, [target, AGENT_URL]);

  const decide = useCallback(
    async (approved: boolean) => {
      if (!sessionId) return;
      setApproving(true);
      try {
        await fetch(`${AGENT_URL}/approve/${sessionId}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ approved }),
        });
      } catch {
        setError("承認の送信に失敗しました");
      } finally {
        setApproving(false);
        setApproval(null);
        setShowDiff(false);
      }
    },
    [sessionId, AGENT_URL],
  );

  const running = status.state !== "idle" && status.state !== "done";
  const tone = statusTone(status.state);
  const legend = [
    { c: "#FF5571", t: "侵入成功", tc: "#FF8198" },
    { c: "#F3B64B", t: "試行中", tc: "#F3B64B" },
    { c: "#5FD08F", t: "防御済み", tc: "#7FE0A8" },
    { c: "#55627C", t: "未到達", tc: "#8392AC" },
  ];

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* ===== HEADER ===== */}
      <header
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: 18,
          padding: "16px 24px",
          borderBottom: "1px solid var(--line)",
          background: "var(--panel)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 13, minWidth: 0 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 9,
              background: "#152238",
              border: "1px solid #2A6B7D",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flex: "none",
            }}
          >
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" role="img" aria-label="アンチボディのロゴ">
              <circle cx="6" cy="7" r="2.3" fill="#5ED1E6" />
              <circle cx="18" cy="6" r="2.3" fill="#3A5A7A" />
              <circle cx="17" cy="18" r="2.3" fill="#3A5A7A" />
              <circle cx="7" cy="17" r="2.3" fill="#3A5A7A" />
              <path d="M6 7l11 11M6 7l12-1M18 6v12M7 17L17 18" stroke="#2A6B7D" strokeWidth="1.1" />
            </svg>
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: ".2px", color: "#F2F5FA" }}>アンチボディ</div>
            <div style={{ fontSize: 12, color: "#6B7A92" }}>脆弱性の自動診断ツール</div>
          </div>
        </div>

        {/* 対象URL欄（許可リストのやられ役サイトが初期値） */}
        <label style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <span style={{ fontSize: 12, color: "#6B7A92", whiteSpace: "nowrap" }}>対象</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={running}
            spellCheck={false}
            style={{
              width: 300,
              maxWidth: "48vw",
              padding: "8px 12px",
              borderRadius: 8,
              background: "#0E131E",
              border: "1px solid #2C3850",
              color: "#C2CDDE",
              fontSize: 12.5,
              fontFamily: "var(--font-mono)",
            }}
          />
        </label>

        <div style={{ flex: 1 }} />

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "8px 15px",
            borderRadius: 999,
            background: tone.bg,
            border: `1px solid ${tone.border}`,
          }}
        >
          <span
            className={running ? "antibody-pulse" : undefined}
            style={{ width: 8, height: 8, borderRadius: "50%", background: tone.dot, boxShadow: `0 0 9px ${tone.dot}` }}
          />
          <span style={{ fontSize: 13, fontWeight: 600, color: tone.text }}>{STATUS_LABEL[status.state]}</span>
        </div>

        <div style={{ display: "flex", alignItems: "baseline", gap: 7 }}>
          <span style={{ fontSize: 12, color: "#6B7A92" }}>ラウンド</span>
          <span style={{ fontSize: 17, fontWeight: 700, fontFamily: "var(--font-mono)", color: "#F2F5FA" }}>
            {status.round}
          </span>
          <span style={{ fontSize: 12, color: "#44506A" }}>/ {status.maxRounds || "—"}</span>
        </div>

        <button
          onClick={start}
          disabled={running}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "9px 18px",
            borderRadius: 8,
            background: running ? "#172033" : "#1C7A48",
            border: `1px solid ${running ? "#2C3850" : "#39C078"}`,
            color: running ? "#6B7A92" : "#EAFBF1",
            fontSize: 13,
            fontWeight: 700,
            cursor: running ? "default" : "pointer",
            fontFamily: "inherit",
          }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M6 4l14 8-14 8V4z" fill="currentColor" />
          </svg>
          {status.state === "done" ? "もう一度診断" : "診断を開始"}
        </button>
      </header>

      {error && (
        <div
          style={{
            padding: "10px 24px",
            background: "#2A1420",
            borderBottom: "1px solid #6E2438",
            color: "#FF8198",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {/* ===== BODY ===== */}
      <div style={{ flex: 1, display: "flex", flexWrap: "wrap", alignItems: "stretch" }}>
        {/* LEFT: 侵入マップ */}
        <section
          style={{
            flex: "1 1 600px",
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            borderRight: "1px solid var(--line)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              flexWrap: "wrap",
              padding: "16px 24px",
              borderBottom: "1px solid var(--line)",
            }}
          >
            <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: "#C2CDDE" }}>侵入マップ</h2>
            <div style={{ display: "flex", gap: 16, fontSize: 11, fontFamily: "var(--font-mono)", flexWrap: "wrap" }}>
              {legend.map((l) => (
                <span key={l.t} style={{ display: "flex", alignItems: "center", gap: 6, color: l.tc }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: l.c }} />
                  {l.t}
                </span>
              ))}
            </div>
          </div>
          <div
            style={{
              flex: 1,
              position: "relative",
              minHeight: 440,
              background: "radial-gradient(circle at 42% 46%, #16203200 0%, #0F1420 72%)",
            }}
          >
            {graph.nodes.length === 0 ? (
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#56647E",
                  fontSize: 13,
                  textAlign: "center",
                  padding: 24,
                }}
              >
                {running ? "対象を偵察しています…" : "「診断を開始」で、やられ役サイトへの侵入実証が始まります"}
              </div>
            ) : (
              <IntrusionMap graph={graph} />
            )}
          </div>
        </section>

        {/* RIGHT: 数値 + 診断の経過 */}
        <aside style={{ flex: "1 1 400px", minWidth: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "22px 26px 18px", borderBottom: "1px solid var(--line)" }}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 1,
                background: "var(--line)",
                border: "1px solid var(--line)",
                borderRadius: 10,
                overflow: "hidden",
              }}
            >
              <Stat label="発見した脆弱性" value={String(stats.found)} color="#F2F5FA" mono />
              <Stat label="到達した深さ" value={stats.depth} color="#F3B64B" />
              <Stat label="修復済み" value={String(stats.patched)} color="#5FD08F" mono />
              <Stat label="抜いたレコード" value={stats.records.toLocaleString()} color="#FF8198" mono />
            </div>
          </div>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", padding: "20px 26px 18px", minHeight: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 15 }}>
              <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: "#C2CDDE" }}>診断の経過</h2>
              {running && (
                <span
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 11,
                    color: "#5FD08F",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <span
                    className="antibody-pulse"
                    style={{ width: 6, height: 6, borderRadius: "50%", background: "#5FD08F", boxShadow: "0 0 6px #5FD08F" }}
                  />
                  実行中
                </span>
              )}
            </div>
            <div
              className="antibody-scroll"
              style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 13, maxHeight: "46vh" }}
            >
              {logs.length === 0 && (
                <div style={{ fontSize: 13, color: "#56647E" }}>ここにエージェントの思考と行動が実況で流れます。</div>
              )}
              {logs.map((l, i) => {
                const a = LOG_ACCENT[l.level];
                return (
                  <div
                    key={i}
                    style={{
                      paddingLeft: a.border === "transparent" ? 0 : 12,
                      borderLeft: a.border === "transparent" ? "none" : `3px solid ${a.border}`,
                    }}
                  >
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: a.ts, marginBottom: 2 }}>
                      {l.ts} {l.phase}
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        color: a.text,
                        lineHeight: 1.55,
                        fontWeight: l.level === "info" ? 400 : 500,
                      }}
                    >
                      {l.text}
                    </div>
                  </div>
                );
              })}
              <div ref={logEndRef} />
            </div>
          </div>
        </aside>
      </div>

      {/* ===== LOOP BAND ===== */}
      <section style={{ borderTop: "1px solid var(--line)", background: "var(--panel)" }}>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "stretch" }}>
          <div
            style={{
              padding: "14px 24px",
              fontSize: 13,
              fontWeight: 600,
              color: "#8392AC",
              borderRight: "1px solid var(--line)",
              whiteSpace: "nowrap",
              display: "flex",
              alignItems: "center",
            }}
          >
            修正と再チェック
            {loop && loop.patched.length > 0 && (
              <span style={{ marginLeft: 10, fontSize: 11, color: "#5FD08F", fontFamily: "var(--font-mono)" }}>
                修復 {loop.patched.length} 件
              </span>
            )}
          </div>
          {(loop?.steps ?? [
            { key: "cause", label: "侵入経路を解析", state: "pending" },
            { key: "gen", label: "修正コードを生成", state: "pending" },
            { key: "approve", label: "承認して適用", state: "pending" },
            { key: "reprove", label: "もう一度試して確認", state: "pending" },
          ]).map((s, i, arr) => (
            <LoopStepCell key={s.key} label={s.label} state={s.state} last={i === arr.length - 1} />
          ))}
        </div>

        {/* 承認バー */}
        {approval && status.state === "awaiting_approval" && (
          <div>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: 15,
                padding: "16px 26px",
                borderTop: "1px solid var(--line)",
                background: "#0E131E",
              }}
            >
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flex: "none" }}>
                <path d="M12 3l9 16H3L12 3z" stroke="#F3B64B" strokeWidth="1.6" strokeLinejoin="round" />
                <path d="M12 10v4" stroke="#F3B64B" strokeWidth="1.8" strokeLinecap="round" />
                <circle cx="12" cy="17" r="1" fill="#F3B64B" />
              </svg>
              <div style={{ flex: "1 1 300px", minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: "#F2F5FA" }}>
                  {approval.name}の修正コードの適用には承認が必要です
                </div>
                <div style={{ fontSize: 12, color: "#8392AC", marginTop: 3, lineHeight: 1.5 }}>{approval.summary}</div>
                <div style={{ fontSize: 11, color: "#6B7A92", marginTop: 3, fontFamily: "var(--font-mono)" }}>
                  {approval.location} · 生成元: {approval.source}
                </div>
              </div>
              <div style={{ display: "flex", gap: 11 }}>
                <button
                  onClick={() => setShowDiff((v) => !v)}
                  style={{
                    padding: "11px 19px",
                    borderRadius: 8,
                    background: "transparent",
                    border: "1px solid #2C3850",
                    color: "#C2CDDE",
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  {showDiff ? "差分を隠す" : "差分を見る"}
                </button>
                <button
                  onClick={() => decide(false)}
                  disabled={approving}
                  style={{
                    padding: "11px 19px",
                    borderRadius: 8,
                    background: "transparent",
                    border: "1px solid #5A2733",
                    color: "#FF8198",
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: "pointer",
                    fontFamily: "inherit",
                  }}
                >
                  見送る
                </button>
                <button
                  onClick={() => decide(true)}
                  disabled={approving}
                  style={{
                    padding: "11px 21px",
                    borderRadius: 8,
                    background: "#2FA866",
                    border: "1px solid #39C078",
                    color: "#06160D",
                    fontSize: 13,
                    fontWeight: 700,
                    cursor: approving ? "default" : "pointer",
                    fontFamily: "inherit",
                    opacity: approving ? 0.6 : 1,
                  }}
                >
                  {approving ? "送信中…" : "承認して適用"}
                </button>
              </div>
            </div>
            {showDiff && (
              <pre
                style={{
                  margin: 0,
                  padding: "16px 26px",
                  borderTop: "1px solid var(--line)",
                  background: "#0A0E17",
                  color: "#C2CDDE",
                  fontFamily: "var(--font-mono)",
                  fontSize: 12,
                  lineHeight: 1.6,
                  overflowX: "auto",
                  whiteSpace: "pre",
                }}
              >
                {renderDiff(approval.diff)}
              </pre>
            )}
          </div>
        )}
      </section>

      {report && status.state === "done" && <ReportBar report={report} />}
    </div>
  );
}

function Stat({ label, value, color, mono }: { label: string; value: string; color: string; mono?: boolean }) {
  return (
    <div style={{ background: "#141A26", padding: "14px 18px" }}>
      <div style={{ fontSize: 12, color: "#6B7A92" }}>{label}</div>
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          color,
          marginTop: 2,
          fontFamily: mono ? "var(--font-mono)" : "var(--font-display)",
        }}
      >
        {value}
      </div>
    </div>
  );
}

function LoopStepCell({ label, state, last }: { label: string; state: string; last: boolean }) {
  const bg = state === "active" ? "#1C1708" : "transparent";
  const icon =
    state === "done" ? (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flex: "none" }}>
        <circle cx="12" cy="12" r="11" fill="#11271B" />
        <path d="M6.5 12.3l3.6 3.6L17.5 8.4" stroke="#5FD08F" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ) : state === "active" ? (
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
        className="antibody-pulse"
        style={{ flex: "none" }}
      >
        <circle cx="12" cy="12" r="11" fill="#2A2108" stroke="#F3B64B" strokeWidth="1.6" />
        <path d="M12 7v5l3 2" stroke="#F3B64B" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    ) : (
      <span style={{ width: 16, height: 16, border: "2px solid #39465E", borderRadius: "50%", flex: "none" }} />
    );
  const titleColor = state === "done" ? "#5FD08F" : state === "active" ? "#F3B64B" : "#AEB9CC";
  const subColor = state === "done" ? "#6B7A92" : state === "active" ? "#B08E4C" : "#56647E";
  const sub = state === "done" ? "完了" : state === "active" ? "実行中" : "待機";
  return (
    <div
      style={{
        flex: "1 1 160px",
        padding: "14px 20px",
        borderRight: last ? "none" : "1px solid #1C2434",
        display: "flex",
        alignItems: "center",
        gap: 11,
        background: bg,
      }}
    >
      {icon}
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: titleColor }}>{label}</div>
        <div style={{ fontSize: 11, color: subColor, fontFamily: "var(--font-mono)" }}>{sub}</div>
      </div>
    </div>
  );
}

function ReportBar({ report }: { report: Report }) {
  return (
    <section style={{ borderTop: "1px solid var(--line)", background: "#0E131E", padding: "18px 26px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M5 4h10l4 4v12H5V4z" stroke="#5FD08F" strokeWidth="1.6" strokeLinejoin="round" />
          <path d="M8 12h8M8 16h8M8 8h3" stroke="#5FD08F" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: "#F2F5FA" }}>診断レポート</h2>
        <span style={{ fontSize: 12, color: "#6B7A92", fontFamily: "var(--font-mono)" }}>
          発見 {report.found} · 修復 {report.patched} · 到達 {report.depth} · 抜いたレコード{" "}
          {report.records.toLocaleString()}
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
        {report.findings.map((f) => {
          const state = f.defended ? "defended" : f.breached ? "breached" : "safe";
          const col =
            state === "defended" ? "#5FD08F" : state === "breached" ? "#FF8198" : "#8392AC";
          const tag = state === "defended" ? "修復済み" : state === "breached" ? "未修復" : "影響なし";
          return (
            <div
              key={f.vuln}
              style={{
                flex: "1 1 220px",
                minWidth: 0,
                border: "1px solid var(--line)",
                borderRadius: 10,
                padding: "12px 15px",
                background: "#141A26",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: "#E7EDF6" }}>{f.name}</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: col, fontFamily: "var(--font-mono)" }}>{tag}</span>
              </div>
              <div style={{ fontSize: 11.5, color: "#6B7A92", marginTop: 5, lineHeight: 1.5 }}>
                {f.location} · 重大度 {f.severity}
              </div>
              <div style={{ fontSize: 12, color: "#9FB0C8", marginTop: 6, lineHeight: 1.5 }}>対策: {f.fix}</div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// 差分の追加行/削除行に色を付けて見やすくする（簡易ハイライト）。
function renderDiff(diff: string) {
  return diff.split("\n").map((line, i) => {
    let color = "#8392AC";
    if (line.startsWith("+") && !line.startsWith("+++")) color = "#7FE0A8";
    else if (line.startsWith("-") && !line.startsWith("---")) color = "#FF8198";
    else if (line.startsWith("@@")) color = "#5ED1E6";
    return (
      <span key={i} style={{ color, display: "block" }}>
        {line || " "}
      </span>
    );
  });
}
