"""A support agent that works for the merchant and can only reach PayPal
through the payment firewall.

python agent.py                       interactive chat
python agent.py "refund $10 on ..."   one request, then exit

Works with any OpenAI-compatible chat API. Set in .env:
  LLM_API_KEY    your key
  LLM_MODEL      model name
  LLM_BASE_URL   only if the provider is not OpenAI
"""
import asyncio
import json
import os
import sys

from dotenv import load_dotenv
from fastmcp import Client

from proxy import build_proxy

load_dotenv()

# The agent only needs a handful of PayPal's 28 tools. Fewer tools means
# fewer mistakes and a smaller surface for the firewall to guard.
AGENT_TOOLS = os.getenv(
    "AGENT_TOOLS",
    "create_refund,get_refund,get_order,list_invoices,send_invoice,"
    "accept_dispute_claim,cancel_subscription,update_plan",
).split(",")

SYSTEM = """You are a customer-support agent for a small online shop. You act on
the shop's PayPal account using the tools provided.

Every tool call passes through a payment firewall that enforces the owner's
spending rules. When a call is blocked or held, tell the user plainly what
happened and why, using the firewall's own reason. Never try to get around a
rule, for example by splitting one refund into several smaller ones. If a
request is held for approval, say which request number is waiting and stop.
Amounts are in USD. Be brief.

Tool-use rules:
- Copy IDs exactly as the user gave them.
- For create_refund, "amount" must be an object, for example
  {"value": "10.00", "currency_code": "USD"}. Never pass a bare number or string.
- Make one tool call per request. If it is blocked or held, do not call it again
  with different values; report the firewall's message word for word.
- Never invent rules. The only reasons that exist are the ones the firewall returns."""


# Some providers (Gemini in particular) reject or stall on rich JSON Schema.
# Keep only the parts every provider understands.
DROP_KEYS = {"$schema", "additionalProperties", "pattern", "default", "format",
             "maxLength", "minLength", "maxItems", "minItems"}


def simplify(node):
    if isinstance(node, list):
        return [simplify(n) for n in node]
    if not isinstance(node, dict):
        return node
    if "anyOf" in node:
        options = [o for o in node["anyOf"] if o.get("type") != "null"]
        merged = {k: v for k, v in node.items() if k != "anyOf"}
        merged.update(options[0] if options else {"type": "string"})
        node = merged
    out = {}
    for key, value in node.items():
        if key in DROP_KEYS:
            continue
        if key == "properties" and isinstance(value, dict):
            out[key] = {name: simplify(sub) for name, sub in value.items()}
        else:
            out[key] = simplify(value)
    return out


def to_function(tool) -> dict:
    schema = simplify(dict(tool.input_schema))
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": (tool.description or "").strip()[:1000],
            "parameters": schema,
        },
    }


def make_llm():
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ["LLM_API_KEY"],
        base_url=os.getenv("LLM_BASE_URL") or None,
        timeout=90,       # fail fast instead of hanging
        max_retries=0,    # show rate-limit errors instead of silently waiting
    )
    model = os.environ["LLM_MODEL"]

    def chat(messages, tools):
        reply = client.chat.completions.create(model=model, messages=messages, tools=tools)
        return reply.choices[0].message

    return chat


async def run_turn(client, chat, tools, messages, on_event=print) -> str:
    """Let the model call tools until it produces a final answer."""
    for _ in range(8):
        on_event("  (asking the model...)")
        try:
            msg = await asyncio.to_thread(chat, messages, tools)
        except Exception as exc:
            return f"The model call failed: {type(exc).__name__}: {exc}"
        calls = msg.tool_calls or []
        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                **({"tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.function.name, "arguments": c.function.arguments}}
                    for c in calls]} if calls else {}),
            }
        )
        if not calls:
            return msg.content or ""
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            on_event(f"  -> agent calls {call.function.name} {json.dumps(args)}")
            try:
                result = await client.call_tool(call.function.name, args)
                output = "\n".join(getattr(p, "text", "") for p in result.content)
            except Exception as exc:          # firewall DENY / HOLD arrive here
                output = f"ERROR: {exc}"
            on_event(f"  <- {output[:300]}")
            messages.append({"role": "tool", "tool_call_id": call.id, "content": output[:6000]})
    return "Stopped: too many tool calls in one request."


async def main():
    chat = make_llm()
    async with Client(build_proxy()) as client:
        tools = [to_function(t) for t in await client.list_tools() if t.name in AGENT_TOOLS]
        messages = [{"role": "system", "content": SYSTEM}]
        if len(sys.argv) > 1:
            messages.append({"role": "user", "content": " ".join(sys.argv[1:])})
            print("\nAgent:", await run_turn(client, chat, tools, messages))
            return
        print("Support agent ready. Type a request, or 'quit'.")
        while True:
            try:
                user = input("\nYou: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user.lower() in ("quit", "exit"):
                break
            if user:
                messages.append({"role": "user", "content": user})
                print("\nAgent:", await run_turn(client, chat, tools, messages))


if __name__ == "__main__":
    asyncio.run(main())
