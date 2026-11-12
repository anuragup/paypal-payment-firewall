# PayPal Payment Firewall for AI Agents

A drop-in proxy that sits between any AI agent and PayPal. Every PayPal action the
agent attempts is checked against rules you write, logged, and then allowed, held
for a human, or blocked, before it can reach your PayPal account.

Built for the PayPal AI Hackathon ("Build What's Next with PayPal and AI").

## The problem

PayPal's MCP server lets AI agents issue refunds, send invoices, cancel
subscriptions and settle disputes. Access today is all or nothing: an agent that
can refund $5 can also refund $5,000. Agents misread instructions, can be talked
into things by a malicious message, and do not always format requests correctly.

## What this does

```
AI agent  ->  Payment Firewall (this project)  ->  PayPal MCP server  ->  PayPal
                    |
                    +-- policy.yaml   rules, in plain text
                    +-- firewall.db   audit log of every decision
                    +-- dashboard     approve / reject / freeze
```

The firewall is itself an MCP server. It exposes PayPal's tools unchanged, so an
agent connects to it exactly as it would to PayPal's own server and needs no code
changes. The rules are enforced in ordinary Python, never by a language model:
the agent proposes, code decides, PayPal executes.

For each tool call the firewall returns one of three decisions:

| Decision | Meaning |
|---|---|
| ALLOW | Within every rule. Forwarded to PayPal. |
| HOLD | Needs a human. The agent is told which request is waiting; it goes through on retry once approved. |
| DENY | Breaks a rule. Never reaches PayPal; the agent is told why. |

## Features

- **Per-action limits**, for example no single refund above $50.
- **Human approval** above a threshold, with single-use approvals.
- **Daily budgets**, which stop an agent splitting one large refund into many small ones.
- **Always-approve and always-deny tools**, for example accepting a dispute or changing a plan's price.
- **Kill switch**: one button freezes every money-moving action.
- **Tolerant amount parsing**: `500`, `"500"`, `"$500.00"` and `{"value": "500"}` are all read as $500, because real agents do not always follow the schema. A refund with no readable amount is treated as a possible full refund and held.
- **Audit log** of every call, decision and reason, in SQLite.
- **Dashboard** showing the log, pending approvals, today's refund spend, and the active policy.

## Quick start

Requirements: Python 3.11+, Node.js 18+, a PayPal developer account.

```bash
git clone https://github.com/anuragup/paypal-payment-firewall.git && cd paypal-payment-firewall
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then fill it in, see below
```

### 1. PayPal sandbox credentials

1. In the [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/), switch to **Sandbox**.
2. Under **Testing Tools > Sandbox Accounts**, create a **Business** account and a **Personal** account. Use **United States** for both; some countries' sandbox accounts cannot pay each other.
3. Under **Apps & Credentials**, create a **Merchant** app linked to that business account. Enable the **Invoicing** feature.
4. Put the app's Client ID and Secret in `.env`.

Check they work:

```bash
python paypal_auth.py     # prints "OK: got an access token"
python test_policy.py     # checks every rule, no network needed
python test_proxy.py      # lists PayPal's tools through the firewall and blocks a $500 refund
```

If you change the app's features later, run `python reset_token.py` so the next
token carries the new permissions.

### 2. A model for the demo agent

`agent.py` works with any OpenAI-compatible chat API. Set three values in `.env`:

| Provider | `LLM_BASE_URL` | `LLM_API_KEY` |
|---|---|---|
| OpenAI | leave empty | your key |
| Ollama (local, free) | `http://localhost:11434/v1` | `ollama` |
| Others | the provider's OpenAI-compatible URL | your key |

`LLM_MODEL` is the model's name at that provider. It must support tool calling.

### 3. Create something to refund

```bash
python seed_payment.py                 # prints an approval link and an order ID
# open the link, log in as the sandbox PERSONAL account, approve
python seed_payment.py <ORDER_ID>      # prints a capture ID
```

### 4. Run it

```bash
uvicorn dashboard:app --port 8000      # terminal 1, then open http://localhost:8000
python agent.py                        # terminal 2
```

Try these in the agent, with your capture ID:

| Request | Result |
|---|---|
| `Refund 5.00 USD for capture <ID>` | Allowed, refunded by PayPal |
| `Refund 500.00 USD for capture <ID>` | Denied: over the per-action limit |
| `Refund 30.00 USD for capture <ID>` | Held. Click **Approve** on the dashboard, then send the same request again |
| Click **Freeze all payments**, then any refund | Denied: frozen |

## Security model

This is a control on money, so the boundaries matter.

- **The agent cannot approve its own requests.** Approval, rejection and the kill
  switch exist only on the dashboard, which is a separate channel. The firewall
  exposes PayPal's tools to the agent and nothing else; there is no "approve" tool.
- **Rules are enforced in code, not by a model.** Using a language model to decide
  whether a language model may move money would defeat the purpose. No prompt,
  however persuasive, changes what `policy.py` allows.
- **Approvals are single-use and specific.** A refund approval covers one payment
  and one amount, and is consumed when that refund goes through. A different
  amount, or a second attempt, needs a new approval.
- **Unknown is treated as risky.** A refund with no readable amount could be a full
  refund, so it is held and flagged, never waved through.
- **The dashboard is for the account owner.** Set `DASHBOARD_PASSWORD` in `.env`
  and the dashboard and its API require that password (HTTP Basic; any username).
  Without it the dashboard is open, which is only suitable on your own machine.
- **Every decision is recorded** with the request, the amount and the reason.

Not yet covered: separate identities and budgets per agent, multiple approvers
with roles, and HTTPS (put it behind a reverse proxy if exposed).

## The policy file

```yaml
default: allow            # tools with no rule, e.g. read-only lookups

rules:
  create_refund:
    max_amount: 50        # deny above this
    approval_above: 20    # hold for a human above this
    daily_budget: 100     # deny once today's total would pass this
  create_invoice:
    max_amount: 500
  accept_dispute_claim:
    action: approval      # always needs a human
  update_plan:
    action: deny          # never allowed
```

The file is re-read on every call, so edits apply immediately.

## Using it with other agents

The firewall speaks MCP over stdio, so any MCP client that can launch a local
server can use it in place of PayPal's server. A typical client configuration:

```json
{
  "mcpServers": {
    "paypal-firewall": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["/absolute/path/to/proxy.py"]
    }
  }
}
```

## How AI and PayPal are used

- **PayPal**: the official PayPal MCP server (`@paypal/mcp`) for refunds, orders, invoices, disputes and subscriptions, running against the sandbox; the OAuth API for tokens.
- **AI**: a tool-calling support agent (`agent.py`) that acts on the merchant's PayPal account, with every action passing through the firewall. Developed and tested with a local Llama 3.2 model through Ollama.
- **Other tools**: FastMCP for the proxy, FastAPI for the dashboard, SQLite for the audit log. An AI coding assistant (Claude) was used to help write the code.

## Files

| File | Purpose |
|---|---|
| `proxy.py` | The firewall: an MCP proxy with the policy check as middleware |
| `policy.py` | Policy engine, amount parsing, audit log, kill switch |
| `policy.yaml` | The rules |
| `dashboard.py` | Web dashboard and its API |
| `agent.py` | Demo support agent |
| `approvals.py` | Approve or reject from the terminal |
| `seed_payment.py` | Creates a sandbox payment to refund |
| `paypal_auth.py`, `reset_token.py` | Access tokens |
| `test_policy.py`, `test_proxy.py` | Tests |

## Limitations

- A refund approval matches on the capture and the amount. Approvals for other tools match the exact request, so a reworded retry of those is held again.
- The access token is fetched when the proxy starts and lasts a few hours; restart the proxy for long sessions.
- One PayPal account, one policy, one approver. There are no per-agent identities or budgets yet.
- The dashboard's login is a single shared owner password, not individual accounts.
- Amounts are compared as plain numbers; currencies are not converted.

## License

MIT. See [LICENSE](LICENSE).
