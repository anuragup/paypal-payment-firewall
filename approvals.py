"""Review held requests from the terminal (the dashboard will replace this).

python approvals.py              list everything waiting
python approvals.py approve 7    approve request #7
python approvals.py reject 7     reject request #7
python approvals.py log          show the last 20 decisions
"""
import sys
import time

import policy


def show(rows):
    for r in rows:
        when = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        amount = f"{r['amount']:.2f}" if r["amount"] is not None else "-"
        print(f"#{r['id']:<4}{when}  {r['verdict']:5} {r['status']:9} {r['tool']:22} {amount:>8}  {r['reason']}")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    with policy.db() as conn:
        if cmd == "list":
            rows = conn.execute("SELECT * FROM audit WHERE status='pending' ORDER BY id").fetchall()
            show(rows) if rows else print("Nothing is waiting for approval.")
        elif cmd == "log":
            show(reversed(conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 20").fetchall()))
        elif cmd in ("approve", "reject") and len(sys.argv) > 2:
            status = "approved" if cmd == "approve" else "rejected"
            done = conn.execute("UPDATE audit SET status=? WHERE id=? AND status='pending'",
                                (status, int(sys.argv[2]))).rowcount
            print(f"Request #{sys.argv[2]} {status}." if done else "No pending request with that number.")
        else:
            print(__doc__)


main()
