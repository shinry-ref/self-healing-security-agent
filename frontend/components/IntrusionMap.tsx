"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import type { Graph, GraphNode, NodeState } from "./types";

// 侵入マップ：エージェントが見つけた構造を D3-force で自動レイアウトし、
// 状態（侵入成功＝赤／試行中＝琥珀／防御＝緑／未到達＝グレー）で色分けする。

const VIEW_W = 760;
const VIEW_H = 560;

interface SimNode extends SimulationNodeDatum {
  id: string;
  group: GraphNode["group"];
}
type SimLink = SimulationLinkDatum<SimNode>;

const NODE_COLOR: Record<NodeState, { ring: string; core: string; label: string; glow: string | null }> = {
  origin: { ring: "#5ED1E6", core: "#5ED1E6", label: "#9FE4F1", glow: null },
  unreached: { ring: "#55627C", core: "#39465E", label: "#8392AC", glow: null },
  active: { ring: "#F3B64B", core: "#F3B64B", label: "#F3B64B", glow: "#F3B64B" },
  breached: { ring: "#FF5571", core: "#FF5571", label: "#FF8198", glow: "#FF5571" },
  defended: { ring: "#5FD08F", core: "#5FD08F", label: "#7FE0A8", glow: "#5FD08F" },
};

function edgeColor(state: NodeState): { stroke: string; dash?: string; width: number } {
  switch (state) {
    case "breached":
      return { stroke: "#C2384E", width: 2.2 };
    case "active":
      return { stroke: "#B5832E", dash: "6 6", width: 2.2 };
    case "defended":
      return { stroke: "#2F7A52", width: 2.2 };
    default:
      return { stroke: "#283347", width: 1.4 };
  }
}

function radiusOf(group: GraphNode["group"]): number {
  if (group === "root") return 20;
  if (group === "data") return 17;
  return 16;
}

export default function IntrusionMap({ graph }: { graph: Graph }) {
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const posRef = useRef<Record<string, { x: number; y: number }>>({});
  const simRef = useRef<Simulation<SimNode, SimLink> | null>(null);

  // レイアウトはトポロジ（ノードid集合＋エッジ）に依存。状態の色だけ変わるときは再計算しない。
  const topoKey = useMemo(
    () =>
      graph.nodes.map((n) => n.id).sort().join("|") +
      "::" +
      graph.edges.map((e) => `${e.source}>${e.target}`).sort().join("|"),
    [graph.nodes, graph.edges],
  );

  useEffect(() => {
    if (graph.nodes.length === 0) return;
    // 既存の座標を引き継ぎ（更新時に飛ばない）、無ければ中心付近に初期配置
    const simNodes: SimNode[] = graph.nodes.map((n) => {
      const prev = posRef.current[n.id];
      return {
        id: n.id,
        group: n.group,
        x: prev?.x ?? VIEW_W / 2 + (Math.random() - 0.5) * 80,
        y: prev?.y ?? VIEW_H / 2 + (Math.random() - 0.5) * 80,
        fx: n.group === "root" ? VIEW_W * 0.14 : undefined,
        fy: n.group === "root" ? VIEW_H * 0.5 : undefined,
      };
    });
    const simLinks: SimLink[] = graph.edges.map((e) => ({ source: e.source, target: e.target }));

    const sim = forceSimulation<SimNode>(simNodes)
      .force("charge", forceManyBody().strength(-620))
      .force("link", forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(130).strength(0.7))
      .force("center", forceCenter(VIEW_W * 0.54, VIEW_H * 0.5))
      .force("collide", forceCollide(52))
      .alpha(1)
      .alphaDecay(0.045);

    sim.on("tick", () => {
      const pad = 54;
      const next: Record<string, { x: number; y: number }> = {};
      for (const n of simNodes) {
        n.x = Math.max(pad, Math.min(VIEW_W - pad, n.x ?? 0));
        n.y = Math.max(pad, Math.min(VIEW_H - pad, n.y ?? 0));
        next[n.id] = { x: n.x, y: n.y };
      }
      posRef.current = next;
      setPositions(next);
    });

    simRef.current = sim;
    return () => {
      sim.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topoKey]);

  const nodeById = useMemo(() => {
    const m: Record<string, GraphNode> = {};
    for (const n of graph.nodes) m[n.id] = n;
    return m;
  }, [graph.nodes]);

  return (
    <svg
      viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
      width="100%"
      height="100%"
      preserveAspectRatio="xMidYMid meet"
      style={{ display: "block" }}
      role="img"
      aria-label="侵入経路のネットワーク図。攻撃者から各侵入口を経て機密データへ向かう経路を状態別の色で示す"
    >
      <defs>
        <radialGradient id="glowRed" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#FF5571" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#FF5571" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="glowAmber" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#F3B64B" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#F3B64B" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="glowGreen" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#5FD08F" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#5FD08F" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* エッジ（ノードの下に描く） */}
      {graph.edges.map((e, i) => {
        const a = positions[e.source];
        const b = positions[e.target];
        if (!a || !b) return null;
        const c = edgeColor(e.state);
        return (
          <line
            key={`e${i}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke={c.stroke}
            strokeWidth={c.width}
            strokeDasharray={c.dash}
          />
        );
      })}

      {/* ノード */}
      {graph.nodes.map((n) => {
        const p = positions[n.id];
        if (!p) return null;
        const col = NODE_COLOR[n.state];
        const r = radiusOf(n.group);
        const glowId =
          n.state === "breached" ? "glowRed" : n.state === "active" ? "glowAmber" : n.state === "defended" ? "glowGreen" : null;
        return (
          <g key={n.id}>
            {glowId && <circle cx={p.x} cy={p.y} r={r + 24} fill={`url(#${glowId})`} />}
            <circle
              cx={p.x}
              cy={p.y}
              r={r}
              fill="#121826"
              stroke={col.ring}
              strokeWidth={n.state === "active" ? 2.6 : 2.2}
              strokeDasharray={n.state === "unreached" ? "4 4" : undefined}
              className={n.state === "active" ? "mamori-pulse" : undefined}
            />
            <circle cx={p.x} cy={p.y} r={r * 0.34} fill={col.core} />
            <text
              x={p.x}
              y={p.y + r + 17}
              textAnchor="middle"
              fontFamily="var(--font-display)"
              fontSize="13.5"
              fontWeight="600"
              fill={col.label}
            >
              {n.label}
            </text>
            <text
              x={p.x}
              y={p.y + r + 33}
              textAnchor="middle"
              fontFamily="var(--font-mono)"
              fontSize="10.5"
              fill="#6B7A92"
            >
              {nodeById[n.id]?.sub}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
