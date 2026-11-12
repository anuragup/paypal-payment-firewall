"""Checks the rules without touching PayPal. Run: python test_policy.py"""
import os
import tempfile

os.environ["FIREWALL_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import policy  # noqa: E402


def refund(value=None):
    args = {"capture_id": "TESTCAPTURE000001"}
    if value is not None:
        args["amount"] = {"value": str(value), "currency_code": "USD"}
    return args


def check(label, decision, expected):
    ok = "pass" if decision.verdict == expected else "FAIL"
    print(f"{ok}  {label}: {decision.verdict} - {decision.reason}")
    assert decision.verdict == expected


d = policy.evaluate("list_invoices", {}); policy.set_status(d.log_id, "done")
check("read-only tool", d, policy.ALLOW)

d = policy.evaluate("create_refund", refund(10)); policy.set_status(d.log_id, "done")
check("small refund", d, policy.ALLOW)

check("refund over the limit", policy.evaluate("create_refund", refund(500)), policy.DENY)

held = policy.evaluate("create_refund", refund(30))
check("mid-size refund", held, policy.HOLD)
check("same refund retried too early", policy.evaluate("create_refund", refund(30)), policy.HOLD)

policy.set_status(held.log_id, "approved")
d = policy.evaluate("create_refund", refund(30)); policy.set_status(d.log_id, "done")
check("retried after approval", d, policy.ALLOW)

h2 = policy.evaluate("create_refund", {"capture_id": "TESTCAPTURE000009", "amount": {"value": "25.00", "currency_code": "USD"}})
check("another mid-size refund", h2, policy.HOLD)
policy.set_status(h2.log_id, "approved")
reworded = {"capture_id": "testcapture000009", "amount": "25", "note_to_payer": "Sorry!"}
d = policy.evaluate("create_refund", reworded); policy.set_status(d.log_id, "done")
check("approved refund retried with different wording", d, policy.ALLOW)
check("approval does not cover a different amount",
      policy.evaluate("create_refund", {"capture_id": "TESTCAPTURE000009", "amount": "26"}), policy.HOLD)
check("approval is single-use", policy.evaluate("create_refund", refund(30)), policy.HOLD)

for n in (15, 16, 17, 18):  # 10 + 30 + these = 106 > 100
    d = policy.evaluate("create_refund", refund(n))
    if d.verdict == policy.ALLOW:
        policy.set_status(d.log_id, "done")
check("daily budget used up", d, policy.DENY)

check("refund with no amount", policy.evaluate("create_refund", {"capture_id": "TESTCAPTURE000002"}), policy.HOLD)
sloppy = {"capture_id": "TESTCAPTURE000003", "amount": "500"}
check("over-limit refund with a badly formatted amount", policy.evaluate("create_refund", sloppy), policy.DENY)
for odd in ("$500.00", "500 USD", 500, {"value": 500}, {"value": "$500"}):
    check(f"over-limit refund written as {odd!r}",
          policy.evaluate("create_refund", {"capture_id": "TESTCAPTURE000004", "amount": odd}), policy.DENY)
check("blocked tool", policy.evaluate("update_plan", {"plan_id": "P-1"}), policy.DENY)
check("always-approve tool", policy.evaluate("accept_dispute_claim", {"dispute_id": "D-1"}), policy.HOLD)

big = {"currency_code": "USD", "items": [{"name": "x", "quantity": "3", "unit_amount": {"currency_code": "USD", "value": "400"}}]}
check("invoice over the limit", policy.evaluate("create_invoice", big), policy.DENY)
policy.set_frozen(True)
check("small refund while frozen", policy.evaluate("create_refund", refund(1)), policy.DENY)
d = policy.evaluate("list_invoices", {}); policy.set_status(d.log_id, "done")
check("read-only tool while frozen", d, policy.ALLOW)
policy.set_frozen(False)
print("\nAll policy checks passed.")
