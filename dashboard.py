"""Web dashboard for the payment firewall.

    uvicorn dashboard:app --port 8000      then open http://localhost:8000

Shows every decision the firewall has made, and lets a human approve or
reject the requests it is holding. It reads the same SQLite file the proxy
writes to, so it works alongside any agent using the proxy.
"""
import json
import os
import secrets
import time

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import policy

load_dotenv()
PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
basic = HTTPBasic(auto_error=False)


def require_owner(creds: HTTPBasicCredentials | None = Depends(basic)):
    """Only the account owner may view the log, approve requests or use the
    kill switch. Agents have no route to this: it is a separate channel."""
    if not PASSWORD:
        return  # no password set: local development only
    ok = creds is not None and secrets.compare_digest(creds.password.encode(), PASSWORD.encode())
    if not ok:
        raise HTTPException(401, "Owner login required.",
                            headers={"WWW-Authenticate": "Basic realm=firewall"})


app = FastAPI(title="PayPal Payment Firewall", dependencies=[Depends(require_owner)])


def row_to_dict(r) -> dict:
    try:
        args = json.loads(r["args"])
    except ValueError:
        args = {}
    return {
        "id": r["id"],
        "time": time.strftime("%H:%M:%S", time.localtime(r["ts"])),
        "tool": r["tool"],
        "args": args,
        "amount": r["amount"],
        "verdict": r["verdict"],
        "reason": r["reason"],
        "status": r["status"],
    }


@app.get("/api/state")
def state():
    with policy.db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
        counts = {
            r["verdict"]: r["n"]
            for r in conn.execute("SELECT verdict, COUNT(*) AS n FROM audit GROUP BY verdict")
        }
    rules = (policy.load_policy().get("rules") or {})
    refund_rule = rules.get("create_refund") or {}
    items = [row_to_dict(r) for r in rows]
    return {
        "pending": [i for i in items if i["status"] == "pending"][::-1],
        "log": items,
        "counts": {v: counts.get(v, 0) for v in (policy.ALLOW, policy.HOLD, policy.DENY)},
        "refunds_today": policy.spent_today("create_refund"),
        "refund_budget": refund_rule.get("daily_budget"),
        "policy": policy.POLICY_PATH.read_text(),
        "frozen": policy.is_frozen(),
    }


@app.post("/api/freeze/{switch}")
def freeze(switch: str):
    if switch not in ("on", "off"):
        raise HTTPException(404)
    policy.set_frozen(switch == "on")
    return {"frozen": policy.is_frozen()}


@app.post("/api/requests/{request_id}/{action}")
def decide(request_id: int, action: str):
    if action not in ("approve", "reject"):
        raise HTTPException(404)
    status = "approved" if action == "approve" else "rejected"
    with policy.db() as conn:
        changed = conn.execute(
            "UPDATE audit SET status=? WHERE id=? AND status='pending'", (status, request_id)
        ).rowcount
    if not changed:
        raise HTTPException(409, "That request is no longer pending.")
    return {"id": request_id, "status": status}


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PayPal Payment Firewall</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --ink:#16202b; --muted:#667085; --line:#e4e7ec;
          --allow:#0a7d4f; --allow-bg:#e3f6ec; --hold:#9a5b00; --hold-bg:#fdf0d5;
          --deny:#b3261e; --deny-bg:#fde7e5; --accent:#003087; }
  * { box-sizing:border-box; }
  body { margin:0; font:15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; background:var(--bg); color:var(--ink); }
  header { background:var(--accent); color:#fff; padding:18px 28px; display:flex; align-items:center; gap:20px; }
  header div { flex:1; }
  #freeze { background:#fff; color:var(--deny); border:0; padding:9px 18px; }
  #freeze.on { background:var(--deny); color:#fff; }
  #banner { display:none; background:var(--deny); color:#fff; text-align:center; padding:8px; font-weight:600; }
  #banner.on { display:block; }
  .warn { color:var(--deny); font-weight:600; }
  header h1 { margin:0; font-size:20px; font-weight:600; }
  header p { margin:2px 0 0; opacity:.8; font-size:13px; }
  main { max-width:1100px; margin:0 auto; padding:24px 20px 60px; display:grid; gap:20px; }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 18px; }
  .stat .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .stat .value { font-size:28px; font-weight:600; margin-top:2px; }
  .bar { height:6px; background:var(--line); border-radius:3px; margin-top:8px; overflow:hidden; }
  .bar span { display:block; height:100%; background:var(--accent); }
  h2 { margin:0 0 12px; font-size:15px; font-weight:600; }
  .empty { color:var(--muted); margin:0; }
  .pending { display:flex; align-items:center; gap:14px; padding:12px 0; border-top:1px solid var(--line); }
  .pending:first-of-type { border-top:0; padding-top:0; }
  .pending .what { flex:1; }
  .pending .what b { font-weight:600; }
  .pending small { color:var(--muted); display:block; }
  button { font:inherit; border-radius:7px; padding:7px 16px; cursor:pointer; border:1px solid transparent; font-weight:600; }
  .approve { background:var(--allow); color:#fff; }
  .reject { background:#fff; color:var(--deny); border-color:var(--deny); }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th { text-align:left; color:var(--muted); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.04em; padding:0 10px 8px 0; }
  td { padding:9px 10px 9px 0; border-top:1px solid var(--line); vertical-align:top; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
  th.num { text-align:right; }
  code { font:13px ui-monospace, Menlo, monospace; }
  .pill { display:inline-block; padding:1px 9px; border-radius:20px; font-size:12px; font-weight:600; }
  .ALLOW { color:var(--allow); background:var(--allow-bg); }
  .HOLD { color:var(--hold); background:var(--hold-bg); }
  .DENY { color:var(--deny); background:var(--deny-bg); }
  .status { color:var(--muted); font-size:12px; }
  pre { margin:0; font:13px/1.5 ui-monospace, Menlo, monospace; white-space:pre-wrap; color:#344054; }
  details summary { cursor:pointer; font-weight:600; }
  @media (max-width:760px) { .stats { grid-template-columns:repeat(2,1fr); } .hide-sm { display:none; } }
</style>
</head>
<body>
<header>
  <div>
    <h1>PayPal Payment Firewall</h1>
    <p>Every PayPal action an AI agent attempts is checked against your rules before it reaches PayPal.</p>
  </div>
  <button id="freeze" onclick="toggleFreeze()">Freeze all payments</button>
</header>
<div id="banner">All payment actions are frozen. Agents can still read data, but nothing that moves money will go through.</div>
<main>
  <section class="stats">
    <div class="card stat"><div class="label">Allowed</div><div class="value" id="n-allow">0</div></div>
    <div class="card stat"><div class="label">Held for approval</div><div class="value" id="n-hold">0</div></div>
    <div class="card stat"><div class="label">Blocked</div><div class="value" id="n-deny">0</div></div>
    <div class="card stat"><div class="label">Refunds today</div><div class="value" id="spent">$0</div>
      <div class="bar"><span id="spent-bar" style="width:0"></span></div></div>
  </section>

  <section class="card">
    <h2>Waiting for your approval</h2>
    <div id="pending"><p class="empty">Nothing is waiting.</p></div>
  </section>

  <section class="card">
    <h2>Audit log</h2>
    <table>
      <thead><tr><th>#</th><th>Time</th><th>Action</th><th class="num">Amount</th><th>Decision</th><th class="hide-sm">Reason</th></tr></thead>
      <tbody id="log"><tr><td colspan="6" class="empty">No activity yet.</td></tr></tbody>
    </table>
  </section>

  <section class="card">
    <details><summary>Active policy (policy.yaml)</summary><pre id="policy"></pre></details>
  </section>
</main>
<script>
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const money = a => a == null ? '&ndash;' : '$' + Number(a).toFixed(2);
const statusNote = { pending:'waiting', approved:'approved, awaiting retry', rejected:'rejected',
                     used:'resolved', failed:'PayPal returned an error', done:'', pending_call:'' };

let frozen = false;
async function toggleFreeze() {
  await fetch('/api/freeze/' + (frozen ? 'off' : 'on'), { method:'POST' });
  refresh();
}

async function decide(id, action) {
  await fetch(`/api/requests/${id}/${action}`, { method:'POST' });
  refresh();
}

async function refresh() {
  let s;
  try { s = await (await fetch('/api/state')).json(); } catch (e) { return; }
  frozen = s.frozen;
  const fb = document.getElementById('freeze');
  fb.textContent = frozen ? 'Unfreeze payments' : 'Freeze all payments';
  fb.className = frozen ? 'on' : '';
  document.getElementById('banner').className = frozen ? 'on' : '';
  document.getElementById('n-allow').textContent = s.counts.ALLOW;
  document.getElementById('n-hold').textContent = s.counts.HOLD;
  document.getElementById('n-deny').textContent = s.counts.DENY;
  const budget = s.refund_budget;
  document.getElementById('spent').innerHTML = money(s.refunds_today) +
    (budget ? ` <span class="status">of ${money(budget)}</span>` : '');
  document.getElementById('spent-bar').style.width = budget ? Math.min(100, 100 * s.refunds_today / budget) + '%' : '0';

  document.getElementById('pending').innerHTML = s.pending.length ? s.pending.map(p => `
    <div class="pending">
      <div class="what"><b>#${p.id} &middot; <code>${esc(p.tool)}</code> &middot; ${p.amount == null && p.tool === 'create_refund'
          ? '<span class="warn">Amount unknown, may be a full refund</span>' : money(p.amount)}</b>
        <small>${esc(p.reason)}</small><small><code>${esc(JSON.stringify(p.args))}</code></small></div>
      <button class="approve" onclick="decide(${p.id},'approve')">Approve</button>
      <button class="reject" onclick="decide(${p.id},'reject')">Reject</button>
    </div>`).join('') : '<p class="empty">Nothing is waiting.</p>';

  document.getElementById('log').innerHTML = s.log.length ? s.log.map(r => `
    <tr><td>${r.id}</td><td>${r.time}</td><td><code>${esc(r.tool)}</code></td>
      <td class="num">${money(r.amount)}</td>
      <td><span class="pill ${r.verdict}">${r.verdict}</span> <span class="status">${statusNote[r.status] || ''}</span></td>
      <td class="hide-sm">${esc(r.reason)}</td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">No activity yet.</td></tr>';
  document.getElementById('policy').textContent = s.policy;
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
