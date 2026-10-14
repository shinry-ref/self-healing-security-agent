import { ALL_VULNS, type VulnId } from "./types";

// 脆弱性の実行時状態。やられ役サイトは「どの脆弱性が有効か（enabled）」と
// 「どれが修正済みか（patched）」を 1 プロセス内のメモリに保持する。
// エージェントが承認後に修正を適用する＝patched に入れる、という流れで
// 自己修復ループ（破れた→直した→守れた）をコード再デプロイなしに回す。

interface VulnState {
  enabled: Set<VulnId>;
  patched: Set<VulnId>;
  seed: number;
}

// dev の HMR やルートごとのモジュール評価をまたいで 1 つの状態を共有するため
// globalThis に載せる（本番 next start / Cloud Run 単一インスタンスでも同様）。
declare global {
  // eslint-disable-next-line no-var
  var __antibodyVulnState: VulnState | undefined;
}

function randomSubset(seed: number): Set<VulnId> {
  // seed から決定的に「少なくとも3種」を有効化する。再現性のためにLCGを使う。
  let s = seed >>> 0;
  const next = () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
  const picked = new Set<VulnId>();
  for (const id of ALL_VULNS) {
    if (next() < 0.6) picked.add(id);
  }
  while (picked.size < 3) {
    const id = ALL_VULNS[Math.floor(next() * ALL_VULNS.length)];
    picked.add(id);
  }
  return picked;
}

function freshState(): VulnState {
  // 既定はデモの確実性を優先して全5種を有効化（seed=0 の規約）。
  return {
    enabled: new Set<VulnId>(ALL_VULNS),
    patched: new Set<VulnId>(),
    seed: 0,
  };
}

function state(): VulnState {
  if (!globalThis.__antibodyVulnState) {
    globalThis.__antibodyVulnState = freshState();
  }
  return globalThis.__antibodyVulnState;
}

/** その脆弱性が今まさに攻撃可能か（有効かつ未修正）。各脆弱版コードが分岐に使う。 */
export function isVulnerable(id: VulnId): boolean {
  const st = state();
  return st.enabled.has(id) && !st.patched.has(id);
}

/** 修正を適用する（patched へ）。承認後にエージェントの制御呼び出しから使う。 */
export function applyPatch(id: VulnId): void {
  state().patched.add(id);
}

/** 修正を取り消す（デモのやり直し用）。 */
export function unpatch(id: VulnId): void {
  state().patched.delete(id);
}

/**
 * 脆弱性構成を作り直す。seed 未指定（または 0）なら全5種を有効化、
 * それ以外なら seed から決定的な部分集合を有効化（ランダム組込）。
 */
export function reset(seed?: number): VulnState {
  if (seed === undefined || seed === 0) {
    globalThis.__antibodyVulnState = freshState();
  } else {
    globalThis.__antibodyVulnState = {
      enabled: randomSubset(seed),
      patched: new Set<VulnId>(),
      seed,
    };
  }
  return state();
}

export interface VulnSnapshot {
  seed: number;
  vulns: { id: VulnId; enabled: boolean; patched: boolean; vulnerable: boolean }[];
}

/** 現在の構成のスナップショット（制御エンドポイントが返す）。 */
export function snapshot(): VulnSnapshot {
  const st = state();
  return {
    seed: st.seed,
    vulns: ALL_VULNS.map((id) => ({
      id,
      enabled: st.enabled.has(id),
      patched: st.patched.has(id),
      vulnerable: st.enabled.has(id) && !st.patched.has(id),
    })),
  };
}
