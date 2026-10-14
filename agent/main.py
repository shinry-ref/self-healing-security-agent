"""エージェント API 入口（FastAPI）。

1 回の診断で、偵察 → 照合 → 攻撃 → 原因特定 → 修正生成 → 人間承認 → 適用 →
再攻撃で防御証明、という自己修復ループを自律で回し、進行を SSE でフロントへ逐次流す。

エンドポイント：
- POST /diagnose      診断開始（対象URLを受け取り、許可リスト検査を必ず通す）
- GET  /stream/{id}   進行イベントを SSE 配信（log / graph / stats / loop / status / approval / report）
- POST /approve/{id}  修正適用の承認（人間の制御ポイント）

合法性の鉄則：攻撃対象は allowlist に完全一致で載った自作のやられ役サイトだけ。
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from allowlist import allowed_targets, is_allowed
from attack import attack
from cve import match_candidates
from fix import generate_fix
from plugins import PLUGINS
from recon import run_recon
from vulns import ATTACK_ORDER, CATALOG, VulnId

CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "antibody-dev-control")

# 抜けるダミーレコードの目安件数（被害の大きさを数値で見せるため）。プラグイン定義から導出。
RECORDS: dict[VulnId, int] = {vid: p.records for vid, p in PLUGINS.items()}

app = FastAPI(title="アンチボディ エージェント")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ダッシュボードから直接 SSE 購読できるように
    allow_methods=["*"],
    allow_headers=["*"],
)


# ───────────────────────── セッション状態 ─────────────────────────
@dataclass
class Session:
    target: str
    queue: "asyncio.Queue[tuple[str, dict] | None]" = field(default_factory=asyncio.Queue)
    approval_event: asyncio.Event = field(default_factory=asyncio.Event)
    approval_result: bool = True
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"found": 0, "patched": 0, "records": 0, "depth": "—"})

    def emit(self, event: str, data: dict) -> None:
        self.queue.put_nowait((event, data))

    def graph_snapshot(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    async def wait_approval(self) -> bool:
        await self.approval_event.wait()
        self.approval_event.clear()
        return self.approval_result


SESSIONS: dict[str, Session] = {}


class DiagnoseReq(BaseModel):
    target: str | None = None


class ApproveReq(BaseModel):
    approved: bool = True


def _default_target() -> str:
    allowed = allowed_targets()
    return allowed[0] if allowed else "http://localhost:3001"


# ───────────────────────── エンドポイント ─────────────────────────
@app.get("/health")
async def health() -> dict:
    return {"ok": True, "allowed": allowed_targets()}


@app.get("/config")
async def config() -> dict:
    """フロントが対象欄の初期値・選択肢に使う（許可リストのみ公開）。"""
    allowed = allowed_targets()
    return {"targets": allowed, "default": _default_target()}


@app.post("/diagnose")
async def diagnose(req: DiagnoseReq) -> dict:
    target = (req.target or _default_target()).rstrip("/")
    if not is_allowed(target):
        # ここが安全装置の本丸。許可リストに無い相手は実行せず弾く。
        raise HTTPException(
            status_code=403,
            detail="このツールは許可されたやられ役サイトしか診断できません",
        )
    sid = uuid.uuid4().hex[:12]
    sess = Session(target=target)
    SESSIONS[sid] = sess
    asyncio.create_task(run_loop(sess))
    return {"id": sid, "target": target}


@app.get("/stream/{sid}")
async def stream(sid: str) -> StreamingResponse:
    sess = SESSIONS.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="診断セッションが見つかりません")

    async def gen():
        # 接続直後に現在のグラフ・統計を送って画面を初期化
        yield _sse("graph", sess.graph_snapshot())
        yield _sse("stats", sess.stats)
        while True:
            item = await sess.queue.get()
            if item is None:
                break
            event, data = item
            yield _sse(event, data)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/approve/{sid}")
async def approve(sid: str, body: ApproveReq) -> dict:
    sess = SESSIONS.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="診断セッションが見つかりません")
    sess.approval_result = body.approved
    sess.approval_event.set()
    return {"ok": True, "approved": body.approved}


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ───────────────────────── 自己修復ループ ─────────────────────────
def _log(sess: Session, phase: str, text: str, level: str = "info") -> None:
    sess.emit("log", {"phase": phase, "text": text, "level": level})


def _set_node(sess: Session, nid: str, state: str) -> None:
    if nid in sess.nodes:
        sess.nodes[nid]["state"] = state
    for e in sess.edges:
        if e["target"] == nid:
            e["state"] = state


def _build_graph(sess: Session, order: list[VulnId]) -> None:
    """攻撃対象の脆弱性から、攻撃者→侵入口→データ、のノードリンク図を組む。"""
    sess.nodes = {
        "atk": {"id": "atk", "label": "攻撃者", "sub": "エージェント", "state": "origin", "group": "root"}
    }
    sess.edges = []
    for vid in order:
        meta = CATALOG[vid]
        s_id, d_id = f"s_{vid}", f"d_{vid}"
        sess.nodes[s_id] = {
            "id": s_id, "label": meta.location, "sub": meta.name,
            "state": "unreached", "group": "surface", "vuln": vid,
        }
        sess.nodes[d_id] = {
            "id": d_id, "label": meta.data_node_label, "sub": f"{RECORDS[vid]}件",
            "state": "unreached", "group": "data", "vuln": vid,
        }
        sess.edges.append({"source": "atk", "target": s_id, "state": "unreached"})
        sess.edges.append({"source": s_id, "target": d_id, "state": "unreached"})


def _depth_label(sess: Session) -> str:
    breached_data = [n for n in sess.nodes.values() if n["group"] == "data" and n["state"] in ("breached", "defended")]
    if not breached_data:
        return "入口のみ"
    if any(n["state"] == "breached" for n in sess.nodes.values() if n["group"] == "data"):
        return "最深部データ"
    return "権限層"


HEAL_STEPS = [
    ("cause", "侵入経路を解析"),
    ("gen", "修正コードを生成"),
    ("approve", "承認して適用"),
    ("reprove", "もう一度試して確認"),
]


def _emit_loop(sess: Session, round_no: int, max_rounds: int, active: str | None,
               done_keys: set[str], patched: list[str]) -> None:
    steps = []
    for key, label in HEAL_STEPS:
        if key in done_keys:
            state = "done"
        elif key == active:
            state = "active"
        else:
            state = "pending"
        steps.append({"key": key, "label": label, "state": state})
    sess.emit("loop", {"round": round_no, "maxRounds": max_rounds, "steps": steps, "patched": patched})


async def run_loop(sess: Session) -> None:
    control = {"x-control-token": CONTROL_TOKEN}
    patched_names: list[str] = []
    try:
        async with httpx.AsyncClient() as client:
            # 0) やられ役サイトを初期状態へ（全5種を有効化・DBを再シード）
            sess.emit("status", {"state": "recon", "round": 0, "maxRounds": 0})
            try:
                await client.post(sess.target + "/api/control/reset", json={}, headers=control, timeout=10)
            except Exception:
                _log(sess, "準備", "対象の初期化呼び出しに失敗（続行）", "warn")

            # 1) 偵察
            _log(sess, "偵察", f"対象 {sess.target} の構成を調査中…")
            recon = await run_recon(client, sess.target)
            tech = "・".join(recon.tech) if recon.tech else "不明"
            _log(sess, "偵察", f"技術スタックを特定: {tech}")
            if recon.pages:
                _log(sess, "偵察", f"ページ {len(recon.pages)} 件・攻撃面 {len(recon.endpoints)} 件を発見")

            # 2) 照合（脆弱性DB／自前データ）
            candidates = await match_candidates(client, recon.tech)
            _log(sess, "照合", f"脆弱性データベースと照合、候補 {len(candidates)} 件")
            for c in candidates:
                _log(sess, "照合", f"{c.name}（{c.cwe} / {c.owasp}・{c.source}）")

            # 2.5) 実際に有効な脆弱性だけを攻撃順に並べる
            try:
                state = (await client.get(sess.target + "/api/control/state", headers=control, timeout=10)).json()
                enabled = {v["id"] for v in state.get("vulns", []) if v.get("vulnerable")}
            except Exception:
                enabled = set(ATTACK_ORDER)
            order = [v for v in ATTACK_ORDER if v in enabled] or list(ATTACK_ORDER)

            _build_graph(sess, order)
            sess.emit("graph", sess.graph_snapshot())
            max_rounds = len(order)

            # 3) 1 脆弱性 = 1 ラウンド。攻撃 → 自己修復 → 再証明。
            for i, vuln in enumerate(order, start=1):
                meta = CATALOG[vuln]
                s_id, d_id = f"s_{vuln}", f"d_{vuln}"
                sess.emit("status", {"state": "attacking", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, None, set(), patched_names)

                # 攻撃（試行中）
                _set_node(sess, s_id, "active")
                _set_node(sess, d_id, "active")
                sess.emit("graph", sess.graph_snapshot())
                _log(sess, "攻撃", f"{meta.location}へ {meta.name} を試行…", "active")

                res = await attack(client, sess.target, vuln)
                if not res.success:
                    _set_node(sess, s_id, "defended")
                    _set_node(sess, d_id, "defended")
                    sess.emit("graph", sess.graph_snapshot())
                    _log(sess, "攻撃", f"{meta.name}は弾かれた（{res.evidence}）")
                    continue

                # 侵入成功
                _set_node(sess, s_id, "breached")
                _set_node(sess, d_id, "breached")
                sess.stats["found"] += 1
                sess.stats["records"] += RECORDS[vuln]
                sess.stats["depth"] = _depth_label(sess)
                sess.emit("graph", sess.graph_snapshot())
                sess.emit("stats", sess.stats)
                _log(sess, "成功", f"{meta.name}で侵入成功 — {res.evidence}", "success")

                # 自己修復：原因特定 → 修正生成
                sess.emit("status", {"state": "fixing", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, "cause", set(), patched_names)
                _log(sess, "原因特定", f"突破された原因コードを特定中…")
                plan = await generate_fix(vuln, res.evidence)
                _emit_loop(sess, i, max_rounds, "gen", {"cause"}, patched_names)
                _log(sess, "修復案", f"{plan.location} の修正案を生成（{plan.source}）")

                # 承認（人間の制御ポイント）
                sess.emit("status", {"state": "awaiting_approval", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, "approve", {"cause", "gen"}, patched_names)
                sess.emit("approval", {
                    "vuln": vuln, "name": plan.name, "file": plan.file,
                    "location": plan.location, "summary": plan.summary,
                    "diff": plan.diff, "source": plan.source,
                })
                _log(sess, "承認待ち", f"修正コードの適用には承認が必要です（{plan.location}）", "warn")

                approved = await sess.wait_approval()
                if not approved:
                    _log(sess, "承認", "承認されず。この修正は適用しません", "warn")
                    _emit_loop(sess, i, max_rounds, None, {"cause", "gen"}, patched_names)
                    continue

                # 適用（承認後にやられ役サイトへ反映）
                _log(sess, "適用", f"{meta.name}の修正を適用しました")
                try:
                    await client.post(sess.target + "/api/control/patch",
                                      json={"vuln": vuln}, headers=control, timeout=10)
                except Exception:
                    _log(sess, "適用", "修正の反映呼び出しに失敗", "warn")

                # 再攻撃で防御証明
                sess.emit("status", {"state": "reproving", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, "reprove", {"cause", "gen", "approve"}, patched_names)
                _log(sess, "再チェック", "同じ攻撃をもう一度実行して確認…", "active")
                res2 = await attack(client, sess.target, vuln)
                if not res2.success:
                    _set_node(sess, s_id, "defended")
                    _set_node(sess, d_id, "defended")
                    sess.stats["patched"] += 1
                    sess.stats["depth"] = _depth_label(sess)
                    patched_names.append(meta.name)
                    sess.emit("graph", sess.graph_snapshot())
                    sess.emit("stats", sess.stats)
                    _log(sess, "防御確認", f"今度は弾かれた — {res2.evidence}", "success")
                    _emit_loop(sess, i, max_rounds, None,
                               {"cause", "gen", "approve", "reprove"}, patched_names)
                else:
                    _log(sess, "再チェック", f"まだ破れる（{res2.evidence}）", "warn")

            # 4) 完了・レポート（report → status:done の順。done で接続を閉じる前に届かせる）
            sess.stats["depth"] = _depth_label(sess)
            sess.emit("stats", sess.stats)
            sess.emit("report", _build_report(sess, order, patched_names))
            _log(sess, "完了", f"診断を完了。発見 {sess.stats['found']} 件 / 修復 {sess.stats['patched']} 件", "success")
            sess.emit("status", {"state": "done", "round": max_rounds, "maxRounds": max_rounds})
    except Exception as e:  # noqa
        sess.emit("error", {"message": f"診断中にエラー: {e}"})
    finally:
        # 専用の end イベントで、フロントに「もう届くものはない」と伝えてから閉じる
        sess.emit("end", {})
        sess.queue.put_nowait(None)


def _build_report(sess: Session, order: list[VulnId], patched: list[str]) -> dict:
    findings = []
    for vid in order:
        meta = CATALOG[vid]
        node = sess.nodes.get(f"d_{vid}", {})
        findings.append({
            "vuln": vid, "name": meta.name, "severity": meta.severity,
            "location": meta.location, "fix": meta.fix,
            "breached": node.get("state") in ("breached", "defended"),
            "defended": node.get("state") == "defended",
        })
    return {
        "target": sess.target,
        "found": sess.stats["found"],
        "patched": sess.stats["patched"],
        "records": sess.stats["records"],
        "depth": sess.stats["depth"],
        "findings": findings,
    }
