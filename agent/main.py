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
import plugins
from plugins import PLUGINS
from recon import run_recon
import sourcefix
from vulns import ATTACK_ORDER, CATALOG, VulnId

CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "antibody-dev-control")
# 修正の適用方式（propose=提案のみ / file=実ソース書換 / flag=ランタイム切替）。
# 既定は propose：公開URLでは状態を変えず「修正案を提示」するアドバイザリ動作。
FIX_MODE = os.environ.get("FIX_MODE", "propose")

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
    mode: str = ""  # この診断で使う修正モード（file / propose / advisory / flag）。空なら既定。
    details: dict = field(default_factory=dict)  # vuln -> 修正案/指針の詳細（レポート掲載用）
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
    mode: str | None = None  # file / propose / advisory / flag。未指定なら FIX_MODE 既定。


# 選べる修正モード。file は TARGET_REPO がある時だけ有効。
VALID_MODES = ("file", "propose", "advisory", "flag")


def _resolve_mode(requested: str | None) -> str:
    """要求モードを検証し、使えないものは成立する方式へ寄せる。"""
    m = (requested or FIX_MODE or "advisory").strip().lower()
    if m not in VALID_MODES:
        m = "advisory"
    # 自律修正(file)はリポジトリ（＝ソース）がある時だけ実ファイルを書き換える。
    # リポジトリが無い公開構成では flag（対象の安全な実装にHTTPで切替）にフォールバックし、
    # 再攻撃で防御を証明する。どちらも「適用→再証明」まで自律で行う自律修正。
    if m == "file" and not sourcefix.repo_available():
        m = "flag"
    return m


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
    """フロントが対象欄の初期値・選択肢・モード切替に使う（許可リストのみ公開）。"""
    allowed = allowed_targets()
    repo = sourcefix.repo_available()
    return {
        "targets": allowed,
        "default": _default_target(),
        "mode": _resolve_mode(None),      # サーバー既定（FIX_MODE から解決）
        "repoAvailable": repo,            # false のとき file モードは選べない
        "modes": list(VALID_MODES),
    }


@app.post("/diagnose")
async def diagnose(req: DiagnoseReq) -> dict:
    target = (req.target or _default_target()).rstrip("/")
    if not is_allowed(target):
        # ここが安全装置の本丸。許可リストに無い相手は実行せず弾く。
        raise HTTPException(
            status_code=403,
            detail="このツールは許可されたやられ役サイトしか診断できません",
        )
    mode = _resolve_mode(req.mode)
    sid = uuid.uuid4().hex[:12]
    sess = Session(target=target, mode=mode)
    SESSIONS[sid] = sess
    asyncio.create_task(run_loop(sess))
    return {"id": sid, "target": target, "mode": mode}


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


# 修復フェーズの表示ステップ。適用する/しないでラベルと段数を変える。
HEAL_STEPS_FIX = [
    ("cause", "侵入経路を解析"),
    ("gen", "修正コードを生成"),
    ("approve", "修正を適用"),
    ("reprove", "もう一度試して確認"),
]
HEAL_STEPS_PROPOSE = [
    ("cause", "侵入経路を解析"),
    ("gen", "修正案を生成"),
    ("approve", "修正案を提示"),
]


def _emit_loop(sess: Session, round_no: int, max_rounds: int, active: str | None,
               done_keys: set[str], patched: list[str],
               heal_steps: list[tuple[str, str]] = HEAL_STEPS_FIX) -> None:
    steps = []
    for key, label in heal_steps:
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
    # 修正の適用方式。
    #   propose（既定・公開版）: 修正案を提示するだけ。適用も再攻撃もしない（状態を変えない）
    #   file: agent がリポジトリの実ソースを書き換え、HMR で反映して再攻撃で防御証明
    #   flag: やられ役サイトのランタイム状態を control/patch で切替
    mode = _resolve_mode(sess.mode)
    file_mode = mode == "file"            # agent が実ソースを書き換える（ローカル・自律修正）
    advisory_mode = mode == "advisory"    # 外部サイト想定：指針だけ、差分は出さない
    no_apply = mode in ("propose", "advisory")  # 提示のみ（適用も再攻撃もしない）
    black_box = advisory_mode             # 具体差分を出さず一般的な指針で生成
    fix_mode = mode
    heal_steps = HEAL_STEPS_PROPOSE if no_apply else HEAL_STEPS_FIX
    try:
        async with httpx.AsyncClient() as client:
            # 0) やられ役サイトを初期状態へ（全種を有効化・DBを再シード）
            sess.emit("status", {"state": "recon", "round": 0, "maxRounds": 0})
            try:
                await client.post(sess.target + "/api/control/reset", json={}, headers=control, timeout=10)
            except Exception:
                _log(sess, "準備", "対象の初期化呼び出しに失敗（続行）", "warn")
            if file_mode:
                # 前回の実行で書き換えたソースを脆弱版へ戻しておく（やり直しのため）
                sourcefix.restore_all()
                _log(sess, "準備", "実ファイル修正モード：リポジトリのソースを直接編集します")

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
                _emit_loop(sess, i, max_rounds, None, set(), patched_names, heal_steps)

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

                # 自己修復：原因特定 → 修正生成（全モード共通）
                sess.emit("status", {"state": "fixing", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, "cause", set(), patched_names, heal_steps)
                _log(sess, "原因特定", f"突破された原因コードを特定中…")
                plan = await generate_fix(vuln, res.evidence, black_box=black_box)
                _emit_loop(sess, i, max_rounds, "gen", {"cause"}, patched_names, heal_steps)
                _log(sess, "修復案", f"{plan.location} の修正案を生成（{plan.source}）")
                # レポート用に詳細（攻撃リクエスト・ペイロード・証拠・修正）を記録（全モード）
                sess.details[vuln] = {
                    **plan.to_dict(), "mode": fix_mode,
                    "request": plugins.request_line(vuln),  # 例: GET /api/files
                    "payload": res.payload,                 # 送った具体的なクエリ/ボディ
                    "evidence": res.evidence,               # 侵入で得られた結果
                }

                # 提示のみモード（advisory / propose）：承認で止めず、提案を記録して次へ。
                # 開始を押したら全脆弱性を探索し、最後にレポートとして一括提示する。
                if no_apply:
                    sess.stats["proposed"] = sess.stats.get("proposed", 0) + 1
                    sess.emit("stats", sess.stats)
                    kind = "修正案"
                    _log(sess, "提示", f"{meta.name} の{kind}を記録（{plan.source}）。レポートに掲載します", "success")
                    _emit_loop(sess, i, max_rounds, None, {"cause", "gen", "approve"}, patched_names, heal_steps)
                    continue

                # 自律修正モード（file / flag）：承認を待たず自動で適用 → 再証明 → 最後にレポート。
                _emit_loop(sess, i, max_rounds, "approve", {"cause", "gen"}, patched_names, heal_steps)

                # 適用（修正を反映）
                if file_mode:
                    # agent がリポジトリの実ソースを直接書き換える（HMR で反映）
                    ok, where = sourcefix.apply_source_fix(vuln)
                    if ok:
                        _log(sess, "適用", f"{where} を実際に書き換えました（HMRで反映）", "success")
                    else:
                        _log(sess, "適用", f"実ファイルの書き換えに失敗（{where}）", "warn")
                else:
                    # フラグ切替モード：やられ役サイトのランタイム状態を切り替える
                    _log(sess, "適用", f"{meta.name}の修正を適用しました")
                    try:
                        await client.post(sess.target + "/api/control/patch",
                                          json={"vuln": vuln}, headers=control, timeout=10)
                    except Exception:
                        _log(sess, "適用", "修正の反映呼び出しに失敗", "warn")

                # 再攻撃で防御証明（file_mode では HMR の反映を少し待ちながら再試行）
                sess.emit("status", {"state": "reproving", "round": i, "maxRounds": max_rounds})
                _emit_loop(sess, i, max_rounds, "reprove", {"cause", "gen", "approve"}, patched_names, heal_steps)
                _log(sess, "再チェック", "同じ攻撃をもう一度実行して確認…", "active")
                res2 = await attack(client, sess.target, vuln)
                if file_mode:
                    for _ in range(8):
                        if not res2.success:
                            break
                        await asyncio.sleep(1.5)  # next dev の再コンパイル待ち
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
                               {"cause", "gen", "approve", "reprove"}, patched_names, heal_steps)
                else:
                    _log(sess, "再チェック", f"まだ破れる（{res2.evidence}）", "warn")

            # 4) 完了・レポート（report → status:done の順。done で接続を閉じる前に届かせる）
            sess.stats["depth"] = _depth_label(sess)
            sess.emit("stats", sess.stats)
            sess.emit("report", _build_report(sess, order, patched_names, no_apply, mode))
            if advisory_mode:
                _log(sess, "完了", f"診断を完了。発見 {sess.stats['found']} 件 / 修正案 {sess.stats.get('proposed', 0)} 件を提示", "success")
            elif no_apply:
                _log(sess, "完了", f"診断を完了。発見 {sess.stats['found']} 件 / 修正案 {sess.stats.get('proposed', 0)} 件を提示", "success")
            else:
                _log(sess, "完了", f"診断を完了。発見 {sess.stats['found']} 件 / 修復 {sess.stats['patched']} 件", "success")
            sess.emit("status", {"state": "done", "round": max_rounds, "maxRounds": max_rounds})
    except Exception as e:  # noqa
        sess.emit("error", {"message": f"診断中にエラー: {e}"})
    finally:
        # 専用の end イベントで、フロントに「もう届くものはない」と伝えてから閉じる
        sess.emit("end", {})
        sess.queue.put_nowait(None)


def _build_report(sess: Session, order: list[VulnId], patched: list[str],
                  propose_mode: bool = False, mode: str = "") -> dict:
    findings = []
    for vid in order:
        meta = CATALOG[vid]
        node = sess.nodes.get(f"d_{vid}", {})
        breached = node.get("state") in ("breached", "defended")
        d = sess.details.get(vid, {})
        findings.append({
            "vuln": vid, "name": meta.name, "severity": meta.severity,
            "location": meta.location, "fix": meta.fix,
            "breached": breached,
            "defended": node.get("state") == "defended",
            # 提案のみモードでは、見つかった脆弱性に修正案を提示した状態
            "proposed": bool(propose_mode and breached),
            # レポートに掲載する詳細（要約・差分・生成元）。advisory では diff は空。
            "summary": d.get("summary", ""),
            "diff": d.get("diff", ""),
            "source": d.get("source", ""),
            "fixFile": d.get("file", ""),
            # 攻撃の実行内容（どのパスへ・どんなクエリ/ペイロードを送り・何が起きたか）
            "request": d.get("request", ""),
            "payload": d.get("payload", ""),
            "evidence": d.get("evidence", ""),
        })
    return {
        "target": sess.target,
        # 具体モード（file / propose / advisory / flag）。後方互換で propose/apply も解釈可能。
        "mode": mode or ("propose" if propose_mode else "apply"),
        "found": sess.stats["found"],
        "patched": sess.stats["patched"],
        "proposed": sess.stats.get("proposed", 0),
        "records": sess.stats["records"],
        "depth": sess.stats["depth"],
        "findings": findings,
    }
