// エージェントの SSE が流すイベントの型。agent/main.py の emit と一対一に対応する。

export type NodeState =
  | "origin"
  | "unreached"
  | "active"
  | "breached"
  | "defended";

export interface GraphNode {
  id: string;
  label: string;
  sub: string;
  state: NodeState;
  group: "root" | "surface" | "data";
  vuln?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  state: NodeState;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export type LogLevel = "info" | "active" | "success" | "warn";

export interface LogLine {
  phase: string;
  text: string;
  level: LogLevel;
  ts: string; // 受信時刻（フロントで付与）
}

export interface Stats {
  found: number;
  patched: number;
  proposed?: number;
  records: number;
  depth: string;
}

export type LoopStepState = "pending" | "active" | "done";

export interface LoopStep {
  key: string;
  label: string;
  state: LoopStepState;
}

export interface LoopState {
  round: number;
  maxRounds: number;
  steps: LoopStep[];
  patched: string[];
}

export type DiagnoseState =
  | "idle"
  | "recon"
  | "attacking"
  | "fixing"
  | "awaiting_approval"
  | "reproving"
  | "done";

export interface StatusEvent {
  state: DiagnoseState;
  round: number;
  maxRounds: number;
}

export interface Approval {
  vuln: string;
  name: string;
  file: string;
  location: string;
  summary: string;
  diff: string;
  source: string;
  mode?: string; // "propose" | "file" | "flag"
}

export interface Finding {
  vuln: string;
  name: string;
  severity: string;
  location: string;
  fix: string;
  breached: boolean;
  defended: boolean;
  proposed?: boolean;
}

export interface Report {
  target: string;
  mode?: string; // "propose" | "apply"
  found: number;
  patched: number;
  proposed?: number;
  records: number;
  depth: string;
  findings: Finding[];
}
