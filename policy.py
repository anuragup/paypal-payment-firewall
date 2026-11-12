"""Policy engine and audit log for the payment firewall.

Pure Python, no AI: the agent proposes, this code decides.
Decisions: ALLOW, HOLD (wait for a human), DENY.
"""
import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).parent
POLICY_PATH = Path(os.getenv("FIREWALL_POLICY", HERE / "policy.yaml"))
DB_PATH = Path(os.getenv("FIREWALL_DB", HERE / "firewall.db"))

ALLOW, HOLD, DENY = "ALLOW", "HOLD", "DENY"


@dataclass
class Decision:
    verdict: str
    reason: str
    amount: float | None = None
    log_id: int | None = None


# ---------- storage ----------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            tool TEXT NOT NULL,
            args TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            amount REAL,
            verdict TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,      -- done | pending | approved | rejected | used | failed
            result TEXT
        )"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    return conn


def is_frozen() -> bool:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='frozen'").fetchone()
    return bool(row and row["value"] == "1")


def set_frozen(on: bool) -> None:
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('frozen', ?)",
                     ("1" if on else "0",))


def fingerprint(tool: str, args: dict) -> str:
    """Identity of a request, used to match a retry to its approval.

    For refunds this is the capture and the amount, so an agent that rewords
    the same refund ("30" then "30.00", or adds a note) still matches, while a
    different amount or a different payment never does.
    """
    if tool == "create_refund":
        amount = amount_of(tool, args)
        key = {"tool": tool,
               "capture_id": str(args.get("capture_id", "")).strip().upper(),
               "amount": None if amount is None else round(amount, 2)}
    else:
        key = {"tool": tool, "args": args}
    blob = json.dumps(key, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def record(tool, args, amount, verdict, reason, status) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO audit (ts, tool, args, fingerprint, amount, verdict, reason, status)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), tool, json.dumps(args), fingerprint(tool, args), amount,
             verdict, reason, status),
        )
        return cur.lastrowid


def set_status(log_id: int, status: str, result: str | None = None) -> None:
    with db() as conn:
        conn.execute("UPDATE audit SET status=?, result=COALESCE(?, result) WHERE id=?",
                     (status, result, log_id))


def spent_today(tool: str) -> float:
    midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
    with db() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM audit"
            " WHERE tool=? AND verdict=? AND status IN ('done','used') AND ts>=?",
            (tool, ALLOW, midnight),
        ).fetchone()
        return float(row["total"])


# ---------- amount extraction ----------

def _num(value) -> float:
    """Read a number out of 500, "500", "$500.00", "500 USD" or "1,200"."""
    if isinstance(value, bool) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    match = re.search(r"-?\d+(?:\.\d+)?", str(value).replace(",", ""))
    return float(match.group()) if match else 0.0


def amount_of(tool: str, args: dict) -> float | None:
    """Money value of a call, or None when the call does not state one."""
    if tool == "create_refund":
        amount = args.get("amount")
        # Agents do not always follow the schema, so accept {"value": "500"},
        # "500" or 500. Anything unreadable or non-positive counts as unknown.
        if isinstance(amount, dict):
            value = _num(amount.get("value", amount.get("amount")))
        else:
            value = _num(amount)
        if value <= 0:   # some agents put it under another name
            value = max((_num(args.get(k)) for k in ("value", "refund_amount", "total")), default=0.0)
        return value if value > 0 else None
    if tool == "create_order":
        total = sum(
            _num(i.get("itemTotal")) or _num(i.get("itemCost")) * (_num(i.get("quantity")) or 1)
            for i in args.get("items", [])
        )
        return total + _num(args.get("shippingCost")) - _num(args.get("discount"))
    if tool == "create_invoice":
        return sum(
            _num((i.get("unit_amount") or {}).get("value")) * (_num(i.get("quantity")) or 1)
            for i in args.get("items", [])
        )
    return None


# ---------- the decision ----------

def load_policy() -> dict:
    return yaml.safe_load(POLICY_PATH.read_text()) or {}


def evaluate(tool: str, args: dict) -> Decision:
    policy = load_policy()          # re-read each call, so edits apply live
    rule = (policy.get("rules") or {}).get(tool)
    amount = amount_of(tool, args)

    def finish(verdict, reason, status):
        return Decision(verdict, reason, amount, record(tool, args, amount, verdict, reason, status))

    if rule is None:
        if policy.get("default", "allow") == "deny":
            return finish(DENY, f"{tool} is not on the allow-list.", "done")
        return finish(ALLOW, "No rule applies to this tool.", "pending_call")

    if is_frozen():   # kill switch: every guarded action stops, whatever its size
        return finish(DENY, "All payment actions are frozen by the account owner.", "done")

    if rule.get("action") == "deny":
        return finish(DENY, f"{tool} is blocked by policy.", "done")

    limit = rule.get("max_amount")
    if limit is not None and amount is not None and amount > limit:
        return finish(DENY, f"Amount {amount:.2f} is over the per-action limit of {limit:.2f}.", "done")

    budget = rule.get("daily_budget")
    if budget is not None and amount is not None:
        used = spent_today(tool)
        if used + amount > budget:
            return finish(
                DENY,
                f"Daily budget exceeded: {used:.2f} already used today, "
                f"{amount:.2f} more would pass the {budget:.2f} limit.",
                "done",
            )

    threshold = rule.get("approval_above")
    needs_human = (
        rule.get("action") == "approval"
        or (threshold is not None and amount is not None and amount > threshold)
        or (threshold is not None and amount is None)   # e.g. "refund everything"
    )
    if needs_human:
        fp = fingerprint(tool, args)
        with db() as conn:
            prior = conn.execute(
                "SELECT id, status FROM audit WHERE fingerprint=? AND verdict=?"
                " AND status IN ('pending','approved','rejected') ORDER BY id DESC LIMIT 1",
                (fp, HOLD),
            ).fetchone()
        if prior and prior["status"] == "approved":
            set_status(prior["id"], "used")
            return finish(ALLOW, f"Approved by a human (request #{prior['id']}).", "pending_call")
        if prior and prior["status"] == "rejected":
            set_status(prior["id"], "used")
            return finish(DENY, f"A human rejected this request (#{prior['id']}).", "done")
        if prior:
            return Decision(HOLD, f"Still waiting for human approval (request #{prior['id']}).",
                            amount, prior["id"])
        why = (f"Amount {amount:.2f} is above the approval threshold of {threshold:.2f}."
               if amount is not None and threshold is not None
               else f"{tool} always needs human approval."
               if rule.get("action") == "approval"
               else "No amount given, so the full value is unknown.")
        decision = finish(HOLD, why, "pending")
        decision.reason = f"{why} Held as request #{decision.log_id}; retry after it is approved."
        return decision

    return finish(ALLOW, "Within all limits.", "pending_call")
